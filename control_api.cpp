#include <grp.h>
#include <unistd.h>

#include "control_api.hpp"

control_api::control_api(
    std::shared_ptr<spdlog::logger> p_log,
    std::optional<std::string>      p_group,
    on_connect_fn_t                 p_on_connect
):
    m_log(p_log),
    m_on_connect(p_on_connect)
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

    m_log->info("control_api destructed");
}

control_api::session::session(
    key                             p_key,
    boost::asio::io_service        &p_service,
    std::shared_ptr<spdlog::logger> p_log
):
    m_socket(p_service),
    m_service(p_service),
    m_log(p_log)
{}

control_api::session::~session()
{
    m_log->info("session destructed");
}

void
control_api::session::start(key p_key)
{
    handle_reads();
    handle_writes();
}

void
control_api::session::handle_reads()
{
    std::weak_ptr<session> l_self_weak(shared_from_this());

    boost::asio::async_read_until(
        m_socket,
        m_buffer,
        "\n",
        [this, l_self_weak](
            const boost::system::error_code p_error,
            const std::size_t               p_length
        ) {
            std::shared_ptr<session> l_self = l_self_weak.lock();

            if (!l_self) {
                return;
            }

            if (p_error) {
                m_log->info("async_read() error {}", p_error.message());

                handle_disconnect();;

                return;
            }

            try {
                std::istream l_istream(&m_buffer);
                std::string l_line;
                std::getline(l_istream, l_line);

                m_log->trace("got command {}", l_line);

                if (m_on_message.has_value()) {
                    m_on_message.value()(nlohmann::json::parse(l_line));
                }
            } catch (const std::exception &p_error) {
                m_log->warn("connection error {}", p_error.what());

                handle_disconnect();

                return;
            }

            handle_reads();
        }
    );
}

void
control_api::session::handle_writes()
{
    std::shared_ptr<session> l_self(shared_from_this());

    if (m_outgoing.size() == 0) {
        return;
    }

    std::shared_ptr<std::string> l_message = std::make_shared<std::string>(
        m_outgoing.front().dump() + "\n"
    );

    m_outgoing.pop_front();

    boost::asio::async_write(
        m_socket,
        boost::asio::buffer(l_message->c_str(), l_message->size()),
        [this, l_self, l_message](
            const boost::system::error_code p_error,
            const std::size_t               p_length
        ) {
            if (p_error) {
                m_log->info("async_write() error {}", p_error.message());

                handle_disconnect();

                return;
            }

            handle_writes();
        }
    );
}

void
control_api::session::handle_disconnect()
{
    if (m_on_disconnect.has_value()) {
        m_on_disconnect.value()();
    }
}

boost::asio::local::stream_protocol::socket &
control_api::session::get_socket(key p_key)
{
    return m_socket;
}

void
control_api::session::queue_outgoing_json(const nlohmann::json p_message)
{
    std::shared_ptr<session> l_self(shared_from_this());

    m_service.post([this, l_self, p_message]() {
        m_outgoing.push_back(p_message);

        if (m_outgoing.size() == 1) {
            handle_writes();
        }
    });
}

void
control_api::session::set_on_message_cb(on_message_fn_t p_cb)
{
    m_on_message = std::optional<on_message_fn_t>(p_cb);
}

void
control_api::session::set_on_disconnect_cb(on_disconnect_fn_t p_cb)
{
    m_on_disconnect = std::optional<on_disconnect_fn_t>(p_cb);
}

void
control_api::accept()
{
    std::shared_ptr<session> l_session = std::make_shared<session>(
        session::key(),
        m_service,
        m_log
    );

    m_acceptor->async_accept(
        l_session->get_socket(session::key()),
        [this, l_session] (
            const boost::system::error_code p_error
        ) mutable {
            if (p_error) {
                this->m_log->info("async_accept() error {}", p_error.message());

                return;
            }

            m_on_connect(l_session);

            l_session->start(session::key());

            accept();
        }
    );
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
