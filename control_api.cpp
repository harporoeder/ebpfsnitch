#include <sys/select.h>
#include <fcntl.h>
#include <grp.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/un.h>

#include "control_api.hpp"

control_api::control_api(
    std::shared_ptr<spdlog::logger> p_log,
    std::optional<std::string>      p_group,
    std::function<nlohmann::json()> p_get_rules
):
    m_log(p_log),
    m_get_rules(p_get_rules)
{
    const char *const l_path = "/tmp/ebpfsnitch.sock";

    unlink(l_path);

    m_acceptor =
        std::make_unique<boost::asio::local::stream_protocol::acceptor>(
            m_service,
            boost::asio::local::stream_protocol::endpoint(l_path)
        );

    if (p_group) {
        m_log->info("setting socket group {}", p_group.value());

        const struct group *const l_group = getgrnam(
            p_group.value().c_str()
        );

        if (l_group == NULL) {
            throw std::runtime_error("getgrnam()");
        }

        if (chown("/tmp/ebpfsnitch.sock", 0, l_group->gr_gid) == -1) {
            throw std::runtime_error("chown()");
        }

        if (chmod("/tmp/ebpfsnitch.sock", 660) != 0){
            throw std::runtime_error("chmod()");
        }
    } else {
        m_log->info("setting control socket world writable");

        if (chmod("/tmp/ebpfsnitch.sock", 666) != 0){
            throw std::runtime_error("chmod()");
        }
    }

    m_thread = std::thread(&control_api::thread, this);
}

control_api::~control_api()
{
    m_service.stop();
    m_thread.join();
}

control_api::session::session(boost::asio::io_service &p_service):
    m_socket(p_service)
{}

void
control_api::queue_outgoing_json(const nlohmann::json &p_message)
{
    m_log->info("queuing outgoing 1");

    m_service.post([this, p_message]() {
        this->m_log->info("queuing outgoing 2");

        for (auto &p_session : this->m_sessions) {
            p_session->m_outgoing.push_back(p_message);

            if (p_session->m_outgoing.size() == 1) {
                this->handle_writes(p_session);
            }
        }
    });
}

void
control_api::accept()
{
    std::shared_ptr<session> l_session = std::make_shared<session>(m_service);

    m_acceptor->async_accept(
        l_session->m_socket,
        [this, l_session](
            const boost::system::error_code p_error
        ) {
            if (p_error) {
                this->m_log->info("async_accept() error {}", p_error.message());

                return;
            }

            {
                std::lock_guard<std::mutex> l_guard(m_lock);

                m_sessions.insert(l_session);
            }

            this->initial(l_session);

            this->accept();
        }
    );
}

void
control_api::initial(std::shared_ptr<session> p_session)
{
    m_log->info("sending initial ruleset to ui");

    p_session->m_outgoing.push_back({
        { "kind",  "setRules"    },
        { "rules", m_get_rules() }
    });

    this->handle_writes(p_session);
    this->handle_reads(p_session);
}

void
control_api::handle_reads(std::shared_ptr<session> p_session)
{
    boost::asio::async_read_until(
        p_session->m_socket,
        p_session->m_buffer,
        "\n",
        [this, p_session](
            const boost::system::error_code p_error,
            const std::size_t               p_length
        ) {
            if (p_error) {
                this->m_log->info("async_write() error {}", p_error.message());

                this->remove_session(p_session);

                return;
            }

            std::istream l_istream(&p_session->m_buffer);
            std::string m_line;
            std::getline(l_istream, m_line);

            this->m_log->info("got command {}", m_line);

            this->handle_reads(p_session);
        }
    );
}

void
control_api::handle_writes(std::shared_ptr<session> p_session)
{
    if (p_session->m_outgoing.size() == 0) {
        return;
    }

    std::shared_ptr<std::string> l_message = std::make_shared<std::string>(
        p_session->m_outgoing.front().dump() + "\n"
    );

    boost::asio::async_write(
        p_session->m_socket,
        boost::asio::buffer(l_message->c_str(), l_message->size()),
        [this, l_message, p_session](
            const boost::system::error_code p_error,
            const std::size_t               p_length
        ) {
            p_session->m_outgoing.pop_front();

            if (p_error) {
                this->m_log->info("async_write() error {}", p_error.message());

                this->remove_session(p_session);

                return;
            }

            this->handle_writes(p_session);
        }
    );
}

void
control_api::remove_session(std::shared_ptr<session> p_session)
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    m_sessions.erase(p_session);

    m_log->info("removing session, session count is now {}", m_sessions.size());
}

void
control_api::thread()
{
    try {
        accept();

        m_service.run();
    } catch (const std::exception &p_err) {
        m_log->error("control_api::thread() {}", p_err.what());
    }
}
