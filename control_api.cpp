#include <sys/select.h>
#include <fcntl.h>
#include <grp.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/un.h>

#include "ebpfsnitch_daemon.hpp"

void
ebpfsnitch_daemon::control_thread()
{
    try {
        m_log->trace("ebpfsnitch_daemon::control_thread() entry");

        int l_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (l_fd <= 0) {
            throw std::runtime_error("socket()");
        }

        const char *const l_path = "/tmp/ebpfsnitch.sock";

        unlink(l_path);

        struct sockaddr_un l_addr;
        memset(&l_addr, 0, sizeof(l_addr));
        l_addr.sun_family = AF_UNIX;
        strcpy(l_addr.sun_path, l_path);

        if (bind(l_fd, (struct sockaddr*)&l_addr, sizeof(l_addr)) < 0) {
            throw std::runtime_error("bind()");
        }

        if (listen(l_fd, 5) < 0) {
            throw std::runtime_error("listen()");
        }

        if (m_group) {
            m_log->info("setting socket group {}", m_group.value());

            const struct group *const l_group = getgrnam(
                m_group.value().c_str()
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

        fd_set l_fd_set;

        const int l_stop_fd = m_stopper.get_stop_fd();
        const int l_max_fd  = std::max(l_stop_fd, l_fd);

        while (true) {
            FD_ZERO(&l_fd_set);
            FD_SET(l_stop_fd, &l_fd_set);
            FD_SET(l_fd, &l_fd_set);

            const int l_count = select(
                l_max_fd + 1,
                &l_fd_set,
                NULL,
                NULL,
                NULL
            );

            if (l_count == -1) {
                m_log->error("probe_thread() select() error");

                break;
            } else if (FD_ISSET(l_stop_fd, &l_fd_set)) {
                break;
            } else if (FD_ISSET(l_fd, &l_fd_set)) {
                struct sockaddr_un l_client_address;
                socklen_t l_client_address_len = sizeof(l_client_address);

                const int l_client_fd = accept(
                    l_fd,
                    (struct sockaddr *)&l_client_address,
                    &l_client_address_len
                );

                if (l_client_fd < 0) {
                    m_log->error("accept() unix socket error {}", l_client_fd);
                }

                m_log->info("accept unix socket connection");

                try {
                    handle_control(l_client_fd);
                } catch (const std::exception &err) {
                    m_log->error("handle_control failed {}", err.what());
                }

                close(l_client_fd);
            } else {
                m_log->error("control_thread() select() unknown fd");

                break;
            }
        }

        close(l_fd);
    } catch (...) {
        m_log->error("ebpfsnitch_daemon::control_thread()");

        m_stopper.stop();
    }

    m_log->trace("ebpfsnitch_daemon::control_thread() exit");
}

static void
write_all(
    const int          p_write_fd,
    const int          p_stop_fd,
    const std::string &p_buffer
) {
    fd_set l_read_set;
    fd_set l_write_set;

    const int l_max_fd = std::max(p_stop_fd, p_write_fd);
    size_t l_written   = 0;

    while (true) {
        FD_ZERO(&l_read_set);
        FD_ZERO(&l_write_set);

        FD_SET(p_stop_fd, &l_read_set);
        FD_SET(p_write_fd, &l_write_set);

        const int l_status = select(
            l_max_fd + 1,
            &l_read_set,
            &l_write_set,
            NULL,
            NULL
        );

        if (l_status == -1) {
            throw std::runtime_error("write_all() select() failed");
        } else if (FD_ISSET(p_stop_fd, &l_read_set)) {
            throw std::runtime_error("write_all() select() stopped");
        } else if (FD_ISSET(p_write_fd, &l_write_set)) {
            const ssize_t l_wrote = write(
                p_write_fd,
                p_buffer.c_str(),
                p_buffer.size()
            );

            if (l_wrote < 0) {
                throw std::runtime_error(
                    "write_all()" + std::string(strerror(errno))
                );
            } else if (l_wrote == 0) {
                throw std::runtime_error(
                    "write_all() socket closed"
                );
            } else {
                l_written += l_wrote;

                if (l_written == p_buffer.size()) {
                    return;
                }
            }

        } else {
            throw std::runtime_error("write_all() select() unknown fd");
        }
    }
}

class line_reader {
public:
    line_reader(const int p_sock):
        m_position(0),
        m_sock(p_sock)
    {};

    std::optional<std::string>
    poll_line()
    {
        for (uint l_iter = 0; l_iter < 2; l_iter++) {
            const char *const l_end =
                (const char *)memchr(m_buffer, '\n', m_position);

            if (l_end != NULL) {
                const std::string l_result(m_buffer, (size_t)(l_end - m_buffer));

                memcpy(m_buffer, l_end + 1, m_position - (l_end - m_buffer));

                m_position = 0;

                return std::optional<std::string>(l_result);
            } else if (l_iter != 0) {
                return std::nullopt;
            }

            const ssize_t l_status = read(
                m_sock,
                &m_buffer + m_position,
                sizeof(m_buffer) - m_position
            );

            if (l_status < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    return std::nullopt;
                } else {
                    throw std::runtime_error(strerror(errno));
                }
            } else if (l_status == 0) {
                throw std::runtime_error("read socket closed");
            }

            m_position += l_status;
        }
        // impossible
        return std::nullopt;
    }

private:
    size_t m_position;
    int m_sock;
    char m_buffer[1024];
};

void
ebpfsnitch_daemon::handle_control(const int p_sock)
{
    if (fcntl(p_sock, F_SETFL, O_NONBLOCK) == -1) {
        throw std::runtime_error("failed to set O_NONBLOCK");
    }

    const int l_stop_fd = m_stopper.get_stop_fd();

    line_reader l_reader(p_sock);

    bool l_awaiting_action = false;

    {
        m_log->info("sending initial ruleset to ui");

        const nlohmann::json l_json = {
            { "kind",   "setRules"                    },
            { "rules",  m_rule_engine.rules_to_json() }
        };

        write_all(
            p_sock,
            l_stop_fd,
            l_json.dump() + "\n"
        );
    }

    auto l_last_ping = std::chrono::system_clock::now();

    struct pollfd l_poll_fd;
    l_poll_fd.fd     = p_sock;
    l_poll_fd.events = POLLIN;

    while (true) {
        if (m_stopper.should_stop()) {
            break;
        }

        const int l_ret = poll(&l_poll_fd, 1, 50);

        if (l_ret < 0) {
            m_log->error("poll() unix socket error {}", l_ret);

            break;
        }

        if (
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now() - l_last_ping
            ).count() > 500
        ) {
            const nlohmann::json l_json = {
                { "kind", "ping" }
            };

            write_all(
                p_sock,
                l_stop_fd,
                l_json.dump() + "\n"
            );

            l_last_ping = std::chrono::system_clock::now();
        }

        const auto l_line_opt = l_reader.poll_line();

        if (l_line_opt) {
            m_log->info("got command |{}|", *l_line_opt);

            nlohmann::json l_verdict = nlohmann::json::parse(*l_line_opt);

            if (l_verdict["kind"] == "addRule") {
                m_log->info("adding rule");

                const std::string l_rule_id = m_rule_engine.add_rule(l_verdict);

                {
                    l_verdict["ruleId"] = l_rule_id;

                    const nlohmann::json l_json = {
                        { "kind", "addRule" },
                        { "body", l_verdict }
                    };

                    write_all(
                        p_sock,
                        l_stop_fd,
                        l_json.dump() + "\n"
                    );
                }

                process_unhandled();

                l_awaiting_action = false;
            } else if (l_verdict["kind"] == "removeRule") {
                m_log->info("removing rule");

                m_rule_engine.delete_rule(l_verdict["ruleId"]);
            }
        }

        if (l_awaiting_action) {
            continue;
        }

        struct nfq_event_t l_nfq_event;
        
        {
            std::lock_guard<std::mutex> l_guard(m_undecided_packets_lock);

            if (m_undecided_packets.size() == 0) {
                continue;
            }

            l_nfq_event = m_undecided_packets.front();
        }

        const std::shared_ptr<const struct process_info_t> l_info =
            m_connection_manager.lookup_connection_info(l_nfq_event);

        if (!l_info) {
            m_log->error("handle_control has no connection info");

            l_nfq_event.m_queue->send_verdict(
                l_nfq_event.m_nfq_id,
                nfq_verdict_t::DROP
            );

            std::lock_guard<std::mutex> l_guard(m_undecided_packets_lock);
            m_undecided_packets.pop();

            continue;
        }

        const std::optional<std::string> l_domain = l_nfq_event.m_v6
            ? m_dns_cache.lookup_domain_v6(
                l_nfq_event.m_destination_address_v6
            )
            : m_dns_cache.lookup_domain_v4(
                l_nfq_event.m_destination_address
            );

        const std::string l_destination_address = [&]() {
            if (l_nfq_event.m_v6) {
                return ipv6_to_string(l_nfq_event.m_destination_address_v6);
            } else {
                return ipv4_to_string(l_nfq_event.m_destination_address);
            }
        }();

        const std::string l_source_address = [&]() {
            if (l_nfq_event.m_v6) {
                return ipv6_to_string(l_nfq_event.m_source_address_v6);
            } else {
                return ipv4_to_string(l_nfq_event.m_source_address);
            }
        }();

        nlohmann::json l_json = {
            { "kind",               "query"                        },
            { "executable",         l_info->m_executable           },
            { "userId",             l_info->m_user_id              },
            { "processId",          l_info->m_process_id           },
            { "sourceAddress",      l_source_address               },
            { "sourcePort",         l_nfq_event.m_source_port      },
            { "destinationPort",    l_nfq_event.m_destination_port },
            { "destinationAddress", l_destination_address          },
            { "protocol",
                ip_protocol_to_string(l_nfq_event.m_protocol)      }
        };

        if (l_domain.has_value()) {
            l_json["domain"] = l_domain.value();
        }

        if (l_info->m_container_id.has_value()) {
            l_json["container"] = l_info->m_container_id.value();
        }

        write_all(
            p_sock,
            l_stop_fd,
            l_json.dump() + "\n"
        );;

        l_awaiting_action = true;
    }
}