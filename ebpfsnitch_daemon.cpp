#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <thread>
#include <arpa/inet.h>
#include <unordered_map>
#include <mutex>
#include <assert.h>
#include <algorithm>
#include <condition_variable>
#include <poll.h>
#include <sys/un.h>
#include <nlohmann/json.hpp>
#include <exception>
#include <regex>

#include <fcntl.h> 
#include <string.h>
#include <grp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "ebpfsnitch_daemon.hpp"

iptables_raii::iptables_raii(std::shared_ptr<spdlog::logger> p_log):
    m_log(p_log)
{
    m_log->trace("adding iptables rules");

    std::system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    std::system("iptables -I DOCKER-USER -i docker0 ! -o docker0 -j NFQUEUE --queue-num 0");
}

iptables_raii::~iptables_raii()
{
    m_log->trace("removing iptables rules");

    std::system("iptables -D OUTPUT -j NFQUEUE --queue-num 0");
    std::system("iptables -D DOCKER-USER -i docker0 ! -o docker0  -j NFQUEUE --queue-num 0");
}

ebpfsnitch_daemon::ebpfsnitch_daemon(
    std::shared_ptr<spdlog::logger> p_log
):
m_log(p_log),
m_shutdown(false),
m_bpf_wrapper(p_log, "./CMakeFiles/probes.dir/probes.c.o")
{
    m_log->trace("ebpfsnitch_daemon constructor");
    
    m_log->trace("setting up ebpf");

    m_bpf_wrapper.attach_kprobe(
        "msend",
        "security_socket_sendmsg",
        false
    );

    m_bpf_wrapper.attach_kprobe(
        "msendret",
        "security_socket_sendmsg",
        true
    );

    m_bpf_wrapper.attach_kprobe(
        "msend2",
        "tcp_v4_connect",
        false
    );

    m_bpf_wrapper.attach_kprobe(
        "msend2ret",
        "tcp_v4_connect",
        true
    );

    int l_buffer_map_fd = bpf_object__find_map_fd_by_name(
        m_bpf_wrapper.m_object,
        "g_probe_ipv4_events"
    );

    if (l_buffer_map_fd < 0) {
        throw std::runtime_error("bpf_object__find_map_fd_by_name() failed");
    }

    m_ring_buffer = ring_buffer__new(
        l_buffer_map_fd,
        &ebpfsnitch_daemon::bpf_reader_indirect,
        (void *)this,
        NULL
    );

    if (m_ring_buffer == NULL) {
        throw std::runtime_error("ring_buffer__new() failed");
    }
    
    m_nfq_handle = nfq_open();

    if (m_nfq_handle == NULL) {
        throw std::runtime_error("nfq_open() failed");
    }

    if (nfq_unbind_pf(m_nfq_handle, AF_INET) < 0) {
        throw std::runtime_error("nfq_unbind_pf() failed");
    }

    if (nfq_bind_pf(m_nfq_handle, AF_INET) < 0) {
        throw std::runtime_error("nfq_bind_pf() failed");
    }

    m_nfq_queue = nfq_create_queue(
        m_nfq_handle,
        0,
        &ebpfsnitch_daemon::nfq_handler_indirect,
        (void *)this
    );

    if (m_nfq_queue == NULL) {
        throw std::runtime_error("nfq_create_queue() failed");
    }

    const uint32_t l_queue_flags =
        NFQA_CFG_F_UID_GID |
        NFQA_CFG_F_GSO     |
        NFQA_CFG_F_CONNTRACK;

    const int l_flag_status = nfq_set_queue_flags(
        m_nfq_queue,
        l_queue_flags,
        l_queue_flags
    );

    if (l_flag_status != 0) {
        throw std::runtime_error("nfq_set_queue_flags() failed");
    }

    if (nfq_set_mode(m_nfq_queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        throw std::runtime_error("nfq_set_mode() failed");
    }

    m_nfq_fd = nfq_fd(m_nfq_handle);

    if (m_nfq_fd <= 0) {
        throw std::runtime_error("nfq_fd() failed");
    }

    m_iptables_raii = std::make_shared<iptables_raii>(p_log);

    m_filter_thread   = std::thread( &ebpfsnitch_daemon::filter_thread,   this );
    m_probe_thread   = std::thread( &ebpfsnitch_daemon::probe_thread,   this );
    m_control_thread = std::thread( &ebpfsnitch_daemon::control_thread, this );
}

ebpfsnitch_daemon::~ebpfsnitch_daemon()
{
    m_log->trace("ebpfsnitch_daemon destructor");;

    m_log->trace("joining threads");
    m_shutdown.store(true);
    m_control_thread.join();
    m_filter_thread.join();
    m_probe_thread.join();

    nfq_destroy_queue(m_nfq_queue);
    nfq_close(m_nfq_handle);
}

void
ebpfsnitch_daemon::filter_thread()
{
    m_log->trace("ebpfsnitch_daemon::filter_thread() entry");

    char l_buffer[1024 * 64] __attribute__ ((aligned));

    struct pollfd l_poll_fd;
    l_poll_fd.fd     = m_nfq_fd;
    l_poll_fd.events = POLLIN;

    while (true) {
        if (m_shutdown.load()) {
            break;
        }
        
        int l_ret = poll(&l_poll_fd, 1, 1000);

        if (l_ret < 0) {
            m_log->error("poll() error {}", l_ret);

            break;
        } else if (l_ret == 0) {
            continue;
        }

        l_ret = recv(m_nfq_fd, l_buffer, sizeof(l_buffer), 0);

        if (l_ret <= 0) {
            m_log->error("recv() error {}", l_ret);

            break;
        }

        nfq_handle_packet(m_nfq_handle, l_buffer, l_ret);
    }

    m_log->trace("ebpfsnitch_daemon::filter_thread() exit");
}

void
ebpfsnitch_daemon::probe_thread()
{
    m_log->trace("ebpfsnitch_daemon::probe_thread() entry");

    while (!m_shutdown.load()) {
        const int err = ring_buffer__poll(m_ring_buffer, 100);

        if (err < 0) {
            std::cout << "ringbuffer poll error" << std::endl;

            break;
        }
    }

    m_log->trace("ebpfsnitch_daemon::probe_thread() exit");
}

void
ebpfsnitch_daemon::bpf_reader(
    void *const p_data,
    const int   p_data_size
){
    assert(p_data);

    const struct probe_ipv4_event_t *const l_info =
        static_cast<probe_ipv4_event_t *>(p_data);

    if (l_info->m_remove) {
        // m_log->info("got remove command {}", l_info->m_handle);

        return;
    }

    // m_log->info("got protocol {}", l_info->m_family);

    const uint16_t l_source_port      = l_info->m_source_port;
    const uint16_t l_destination_port = ntohs(l_info->m_destination_port);

    const std::string l_destination_address =
        ipv4_to_string(l_info->m_destination_address);

    const std::string l_source_address =
        ipv4_to_string(l_info->m_source_address);

    const auto l_process_info_opt = lookup_process_info(l_info->m_process_id);

    if (!l_process_info_opt) {
        m_log->error("process does not exist {}", l_info->m_process_id);

        return;
    }

    const auto l_process_info = l_process_info_opt.value();

    /*
    m_log->info(
        "got event handle {} uid {} pid {} sourcePort {} sourceAddress {} "
        "destinationPort {} destinationAddress {} protocol {} exe {}",
        l_info->m_handle,
        l_info->m_user_id,
        l_info->m_process_id,
        l_source_port,
        l_source_address,
        l_destination_port,
        l_destination_address,
        l_info->m_family,
        l_process_info.m_executable
    );
    */

    const std::string l_key =
        l_source_address +
        std::to_string(l_source_port) +
        l_destination_address +
        std::to_string(l_destination_port);

    struct connection_info_t l_info2;

    l_info2.m_user_id    = l_info->m_user_id;
    l_info2.m_process_id = l_info->m_process_id;
    l_info2.m_executable = l_process_info.m_executable;
    l_info2.m_container  = l_process_info.m_container_id.value_or("");

    {
        std::lock_guard<std::mutex> l_guard(m_lock);

        m_mapping[l_key] = l_info2;
    }

    process_unassociated();
}

int
ebpfsnitch_daemon::bpf_reader_indirect(
    void *const  p_cb_cookie,
    void *const  p_data,
    const size_t p_data_size
){
    assert(p_cb_cookie);
    assert(p_data);

    class ebpfsnitch_daemon *const l_self =
        (class ebpfsnitch_daemon *const)p_cb_cookie;

    l_self->bpf_reader(p_data, p_data_size);

    return 0;
}

bool
ebpfsnitch_daemon::process_associated_event(
    const struct nfq_event_t       &l_nfq_event,
    const struct connection_info_t &l_info
) {
    const std::optional<bool> l_verdict = m_rule_engine.get_verdict(
        l_nfq_event,
        l_info
    );

    if (l_verdict) {
        if (l_verdict.value()) {
            // m_log->info("verdict allow {}", l_info.m_executable);

            set_verdict(l_nfq_event.m_nfq_id, NF_ACCEPT);

            return true;
        } else {
            // m_log->info("verdict deny {}", l_info.m_executable);
            set_verdict(l_nfq_event.m_nfq_id, NF_DROP);

            return true;
        }
    }

    return false;
}

bool
ebpfsnitch_daemon::process_nfq_event(
    const struct nfq_event_t &l_nfq_event,
    const bool                p_queue_unassociated
) {
    const std::optional<struct connection_info_t> l_optional_info =
        lookup_connection_info(l_nfq_event);

    if (l_optional_info) {
        if (process_associated_event(l_nfq_event, l_optional_info.value())) {
            return true;
        }
    }

    if (p_queue_unassociated) {
        if (l_optional_info) {
            // m_log->info("process_nfq_event queueing undecided");

            std::lock_guard<std::mutex> l_guard(m_undecided_packets_lock);
            m_undecided_packets.push(l_nfq_event);

        } else {
            // m_log->info("process_nfq_event queueing unassociated");

            std::lock_guard<std::mutex> l_guard_undecided(
                m_unassociated_packets_lock
            );

            m_unassociated_packets.push(l_nfq_event);
        }
    }

    return false;
}

int
ebpfsnitch_daemon::nfq_handler(
    struct nfq_q_handle *const p_qh,
    struct nfgenmsg *const     p_nfmsg,
    struct nfq_data *const     p_nfa
){
    struct nfqnl_msg_packet_hdr *l_header = nfq_get_msg_packet_hdr(p_nfa);	

    struct nfq_event_t l_nfq_event;
    l_nfq_event.m_nfq_id = ntohl(l_header->packet_id);
    l_nfq_event.m_user_id = 1337;
    l_nfq_event.m_group_id = 1337;

    unsigned char *l_data = NULL;
    const int l_ret = nfq_get_payload(p_nfa, &l_data);

    if (l_ret < 24) {
        m_log->error("unknown dropping malformed");
        set_verdict(l_nfq_event.m_nfq_id, NF_DROP);
        return 0;
    }

    const ip_protocol_t l_proto =
        static_cast<ip_protocol_t>(*((uint8_t*) (l_data + 9)));

    /*
    if (l_proto != ip_protocol_t::TCP && l_proto != ip_protocol_t::UDP) {
        m_log->error(
            "unknown allowing unhandled protocol {} {}",
            ip_protocol_to_string(l_proto),
            l_nfq_event.m_protocol
        );
        set_verdict(l_nfq_event.m_nfq_id, NF_ACCEPT);
        return 0;
    }
    */

    l_nfq_event.m_protocol            = l_proto;
    l_nfq_event.m_source_address      = *((uint32_t*) (l_data + 12));
    l_nfq_event.m_destination_address = *((uint32_t*) (l_data + 16));
    l_nfq_event.m_timestamp           = nanoseconds();
    
    if (l_proto == ip_protocol_t::TCP || l_proto == ip_protocol_t::UDP) {
        l_nfq_event.m_source_port      = ntohs(*((uint16_t*) (l_data + 20)));
        l_nfq_event.m_destination_port = ntohs(*((uint16_t*) (l_data + 22)));
    } else {
        l_nfq_event.m_source_port      = 0;
        l_nfq_event.m_destination_port = 0;
    }

    if ((nfq_get_skbinfo(p_nfa) & NFQA_SKB_GSO) != 0){
        m_log->error("NFQA_SKB_GSO {}", nfq_event_to_string(l_nfq_event));
    }

    if (nfq_get_uid(p_nfa, &l_nfq_event.m_user_id) == 0) {
        // m_log->error("unknown nfq uid {}", nfq_event_to_string(l_nfq_event));
        // set_verdict(l_nfq_event.m_nfq_id, NF_DROP);
        // return 0;
    }

    if (nfq_get_gid(p_nfa,& l_nfq_event.m_group_id) == 0) {
        // m_log->error("unknown nfq gid");
        // set_verdict(l_nfq_event.m_nfq_id, NF_DROP);
        // return 0;
    }

    const nf_hook_t p_hook =
        static_cast<nf_hook_t>(l_header->hook);

    struct nlif_handle *l_nlif = nlif_open();
    if (l_nlif == NULL) {
        m_log->error("nlif_open() failed");
    }
    nlif_query(l_nlif);

    char l_indev[IFNAMSIZ];
    nfq_get_indev_name(l_nlif, p_nfa, l_indev);

    char l_outdev[IFNAMSIZ];
    nfq_get_outdev_name(l_nlif, p_nfa, l_outdev);

    nlif_close(l_nlif);

    /*
    m_log->info(
        "nfq event "
        "userId {} groupId {} protocol {} sourceAddress {} sourcePort {}"
        " destinationAddress {} destinationPort {} hook {} indev {} outdev {}",
        l_nfq_event.m_user_id,
        l_nfq_event.m_group_id,
        ip_protocol_to_string(p_proto),
        ipv4_to_string(l_nfq_event.m_source_address),
        l_nfq_event.m_source_port,
        ipv4_to_string(l_nfq_event.m_destination_address),
        l_nfq_event.m_destination_port,
        nf_hook_to_string(p_hook),
        l_indev,
        l_outdev
    );
    */

    process_nfq_event(l_nfq_event, true);

    return 0;
}

int
ebpfsnitch_daemon::nfq_handler_indirect(
    struct nfq_q_handle *const p_qh,
    struct nfgenmsg *const     p_nfmsg,
    struct nfq_data *const     p_nfa,
    void *const                p_data
){
    assert(p_data);

    class ebpfsnitch_daemon *const l_self =
        (class ebpfsnitch_daemon *const)p_data;

    return l_self->nfq_handler(p_qh, p_nfmsg, p_nfa);
}

std::optional<struct connection_info_t>
ebpfsnitch_daemon::lookup_connection_info(const nfq_event_t &p_event)
{
    const std::string l_key =
        ipv4_to_string(p_event.m_source_address) +
        std::to_string(p_event.m_source_port) +
        ipv4_to_string(p_event.m_destination_address) +
        std::to_string(p_event.m_destination_port);

    std::lock_guard<std::mutex> l_guard(m_lock);

    if (m_mapping.find(l_key) != m_mapping.end()) {
        return std::optional<struct connection_info_t>(m_mapping[l_key]);
    } else {
        const std::string l_key2 =
            "0.0.0.0" +
            std::to_string(p_event.m_source_port) +
            ipv4_to_string(p_event.m_destination_address) +
            std::to_string(p_event.m_destination_port);
        
        if (m_mapping.find(l_key2) != m_mapping.end()) {
            return std::optional<struct connection_info_t>(m_mapping[l_key2]);
        }

        return std::nullopt;
    }
}

std::optional<bool>
ebpfsnitch_daemon::get_verdict(
    const struct nfq_event_t       &p_nfq_event,
    const struct connection_info_t &p_info
) {
    std::lock_guard<std::mutex> l_guard(m_verdicts_lock);

    if (m_verdicts.find(p_info.m_executable) != m_verdicts.end()) {
        return std::optional<bool>(m_verdicts[p_info.m_executable]);
    } else {
        return std::nullopt;
    }
}

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

        const struct group *const l_group = getgrnam("wheel");

        if (l_group == NULL) {
            throw std::runtime_error("getgrnam()");
        }

        if (chown("/tmp/ebpfsnitch.sock", 0, l_group->gr_gid) == -1) {
            throw std::runtime_error("chown()");
        }

        if (chmod("/tmp/ebpfsnitch.sock", 660) != 0){
            throw std::runtime_error("chmod()");
        }

        struct pollfd l_poll_fd;
        l_poll_fd.fd     = l_fd;
        l_poll_fd.events = POLLIN;

        while (true) {
            if (m_shutdown.load()) {
                break;
            }
            
            int l_ret = poll(&l_poll_fd, 1, 1000);

            if (l_ret < 0) {
                m_log->error("poll() unix socket error {}", l_ret);

                break;
            } else if (l_ret == 0) {
                continue;
            }

            int l_client_fd = accept(
                l_fd,
                (struct sockaddr *)&l_addr,
                (socklen_t*)&l_addr
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
        }

        close(l_fd);
    } catch (...) {
        m_log->error("ebpfsnitch_daemon::control_thread()");

        g_shutdown.notify_all();
    }

    m_log->trace("ebpfsnitch_daemon::control_thread() exit");
}

static void
writeAll(const int p_sock, const std::string &p_buffer)
{
    size_t l_written = 0;

    while (true) {
        const ssize_t l_status = write(
            p_sock,
            p_buffer.c_str(),
            p_buffer.size()
        );

        if (l_status < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                continue;
            } else {
                throw std::runtime_error(strerror(errno));
            }
        } else if (l_status == 0) {
            throw std::runtime_error("write socket closed");
        }

        l_written += l_status;

        if (l_written == p_buffer.size()) {
            return;
        }
    }
}

class line_reader {
public:
    line_reader(const int p_sock):
        m_sock(p_sock),
        m_position(0)
    {};

    std::optional<std::string>
    poll_line()
    {
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

        char *l_end = (char *)memchr(m_buffer, '\n', m_position);

        if (l_end == NULL) {
            return std::nullopt;
        }

        const std::string l_line(m_buffer, l_end - m_buffer);

        m_position = 0;

        return std::optional<std::string>(l_line);
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

    line_reader l_reader(p_sock);

    bool awaitingAction = false;

    {
        m_log->info("sending initial ruleset to ui");

        const nlohmann::json l_json = {
            { "kind",   "setRules"                    },
            { "rules",  m_rule_engine.rules_to_json() }
        };

        const std::string l_json_serialized = l_json.dump() + "\n";
        writeAll(p_sock, l_json_serialized);
    }

    while (true) {
        if (m_shutdown.load()) {
            break;
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

                    const std::string l_json_serialized = l_json.dump() + "\n";
                    m_log->info("writing all");
                    writeAll(p_sock, l_json_serialized);
                }

                process_unhandled();

                awaitingAction = false;
            } else if (l_verdict["kind"] == "removeRule") {
                m_log->info("removing rule");

                m_rule_engine.delete_rule(l_verdict["ruleId"]);
            }
        }

        if (awaitingAction) {
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

        const std::optional<struct connection_info_t> l_optional_info =
            lookup_connection_info(l_nfq_event);

        if (!l_optional_info) {
            m_log->error("handle_control has no connection info");

            set_verdict(l_nfq_event.m_nfq_id, NF_DROP);

            std::lock_guard<std::mutex> l_guard(m_undecided_packets_lock);
            m_undecided_packets.pop();

            continue;
        }

        const struct connection_info_t l_info = l_optional_info.value();

        const nlohmann::json l_json = {
            { "kind",               "query"                        },
            { "executable",         l_info.m_executable            },
            { "userId",             l_nfq_event.m_user_id          },
            { "processId",          l_info.m_process_id            },
            { "sourceAddress",
                ipv4_to_string(l_nfq_event.m_source_address)       },
            { "sourcePort",         l_nfq_event.m_source_port      },
            { "destinationPort",    l_nfq_event.m_destination_port },
            { "destinationAddress",
                ipv4_to_string(l_nfq_event.m_destination_address)  },
            { "container",          l_info.m_container             },
            { "protocol",
                ip_protocol_to_string(l_nfq_event.m_protocol)      }
        };

        const std::string l_json_serialized = l_json.dump() + "\n";

        writeAll(p_sock, l_json_serialized);

        awaitingAction = true;
    }
}

void
ebpfsnitch_daemon::process_unassociated()
{
    std::queue<struct nfq_event_t> l_remaining;

    // m_log->info("process unassociated");

    std::lock_guard<std::mutex> l_guard(m_unassociated_packets_lock);

    while (m_unassociated_packets.size()) {
        struct nfq_event_t l_nfq_event = m_unassociated_packets.front(); 

        const std::optional<struct connection_info_t> l_optional_info =
            lookup_connection_info(l_nfq_event);

        if (l_optional_info) {
            struct connection_info_t l_info = l_optional_info.value();

            if (!process_associated_event(l_nfq_event, l_info)) {
                std::lock_guard<std::mutex> l_guard2(
                    m_undecided_packets_lock
                );

                m_undecided_packets.push(l_nfq_event);
            }
        } else {
            // two seconds
            if (nanoseconds() > (l_nfq_event.m_timestamp + 2000000000 )) {
                m_log->error(
                    "dropping still unassociated {}",
                    nfq_event_to_string(l_nfq_event)
                );

                set_verdict(l_nfq_event.m_nfq_id, NF_DROP);
            } else {
                l_remaining.push(l_nfq_event);    
            }
        }

        m_unassociated_packets.pop();
    }
    
    m_unassociated_packets = l_remaining;
}

void
ebpfsnitch_daemon::process_unhandled()
{
    std::queue<struct nfq_event_t> l_remaining;

    // m_log->info("process unhandled");

    std::lock_guard<std::mutex> l_guard(m_undecided_packets_lock);

    while (m_undecided_packets.size()) {
        struct nfq_event_t l_unhandled = m_undecided_packets.front(); 

        const std::optional<struct connection_info_t> l_optional_info =
            lookup_connection_info(l_unhandled);

        if (l_optional_info) {
            if (!process_associated_event(
                l_unhandled, l_optional_info.value()))
            {
                // m_log->info("still undecided");

                l_remaining.push(l_unhandled);
            }
        } else {
            m_log->error("event unassociated when it should be, dropping");
        }

        m_undecided_packets.pop();
    }
    
    m_undecided_packets = l_remaining;
}

std::string
nfq_event_to_string(const nfq_event_t &p_event)
{
    return
        "userId "              + std::to_string(p_event.m_user_id) +
        " groupId "            + std::to_string(p_event.m_group_id) +
        " sourceAddress "      + ipv4_to_string(p_event.m_source_address) +
        " sourcePort "         + std::to_string(p_event.m_source_port) +
        " destinationAddress " + ipv4_to_string(p_event.m_destination_address) +
        " destinationPort "    + std::to_string(p_event.m_destination_port) +
        " timestamp "          + std::to_string(p_event.m_timestamp);
}

void
ebpfsnitch_daemon::set_verdict(const uint32_t p_id, const uint32_t p_verdict)
{
    std::lock_guard<std::mutex> l_guard(m_response_lock);

    const int l_status = nfq_set_verdict(
        m_nfq_queue,
        p_id,
        p_verdict,
        0,
        NULL
    );

    if (l_status < 0) {
        throw std::runtime_error("nfq_set_verdict failed");
    }
}

std::optional<process_info_t>
ebpfsnitch_daemon::lookup_process_info(const uint32_t p_process_id)
{
    const std::string l_path = 
        "/proc/" +
        std::to_string(p_process_id) +
        "/exe";

    char l_readlink_buffer[1024 * 32];

    const ssize_t l_readlink_status = readlink(
        l_path.c_str(),
        l_readlink_buffer,
        sizeof(l_readlink_buffer) - 1
    );

    if (l_readlink_status == -1) {
        return std::nullopt;
    }

    l_readlink_buffer[l_readlink_status] = '\0';

    const std::string l_path_cgroup = 
        "/proc/" +
        std::to_string(p_process_id) +
        "/cgroup";

    struct process_info_t l_process_info;

    l_process_info.m_executable   = std::string(l_readlink_buffer);
    l_process_info.m_container_id = std::nullopt;

    try {
        const std::string l_cgroup = file_to_string(l_path_cgroup);

        std::regex l_regex(".*/docker/(\\w+)\n"); 
        std::smatch l_match;

        if (std::regex_search(
            l_cgroup.begin(),
            l_cgroup.end(),
            l_match,
            l_regex)
        ){
            l_process_info.m_container_id =
                std::optional<std::string>(l_match[1]);
        }
    } catch (...) {}

    return std::optional<struct process_info_t>(l_process_info);
}