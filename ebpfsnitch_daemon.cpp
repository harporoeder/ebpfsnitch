#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
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

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "dns_parser.hpp"
#include "ebpfsnitch_daemon.hpp"

iptables_raii::iptables_raii(std::shared_ptr<spdlog::logger> p_log):
    m_log(p_log)
{
    m_log->trace("adding iptables rules");

    std::system("iptables --append OUTPUT --jump NFQUEUE --queue-num 0");

    std::system("iptables --append INPUT --jump NFQUEUE --queue-num 1");

    std::system(
        "iptables --insert DOCKER-USER --in-interface docker0 ! "
        "--out-interface docker0 --jump NFQUEUE --queue-num 0"
    );
}

iptables_raii::~iptables_raii()
{
    m_log->trace("removing iptables rules");

    remove_rules();
}

void
iptables_raii::remove_rules()
{
    std::system("iptables --delete OUTPUT --jump NFQUEUE --queue-num 0");

    std::system("iptables --delete INPUT --jump NFQUEUE --queue-num 1");

    std::system(
        "iptables --delete DOCKER-USER --in-interface docker0 ! "
        "--out-interface docker0 --jump NFQUEUE --queue-num 0"
    );
}

ebpfsnitch_daemon::ebpfsnitch_daemon(
    std::shared_ptr<spdlog::logger> p_log
):
m_log(p_log),
m_shutdown(false),
m_bpf_wrapper(p_log, "./CMakeFiles/probes.dir/probes.c.o"),
m_process_manager()
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

    m_ring_buffer = std::make_shared<bpf_wrapper_ring>(
        m_bpf_wrapper.lookup_map_fd_by_name("g_probe_ipv4_events"),
        std::bind(
            &ebpfsnitch_daemon::bpf_reader,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        )
    );

    m_nfq = std::make_shared<nfq_wrapper>(
        0,
        std::bind(
            &ebpfsnitch_daemon::nfq_handler,
            this,
            std::placeholders::_1
        )
    );

    m_nfq_incoming = std::make_shared<nfq_wrapper>(
        1,
        std::bind(
            &ebpfsnitch_daemon::nfq_handler_incoming,
            this,
            std::placeholders::_1
        )
    );

    m_iptables_raii = std::make_shared<iptables_raii>(p_log);

    m_thread_group.push_back(
        std::thread(&ebpfsnitch_daemon::filter_thread, this, m_nfq)
    );

    m_thread_group.push_back(
        std::thread(&ebpfsnitch_daemon::filter_thread, this, m_nfq_incoming)
    );

    m_thread_group.push_back(
        std::thread(&ebpfsnitch_daemon::probe_thread, this)
    );

    m_thread_group.push_back(
        std::thread(&ebpfsnitch_daemon::control_thread, this)
    );
}

ebpfsnitch_daemon::~ebpfsnitch_daemon()
{
    m_log->trace("ebpfsnitch_daemon destructor");;

    m_shutdown.store(true);

    for (auto &l_thread : m_thread_group) {
        l_thread.join();
    }
}

void
ebpfsnitch_daemon::filter_thread(std::shared_ptr<nfq_wrapper> p_nfq)
{
    m_log->trace("ebpfsnitch_daemon::filter_thread() entry");

    char l_buffer[1024 * 64] __attribute__ ((aligned));

    struct pollfd l_poll_fd;

    l_poll_fd.fd     = p_nfq->get_fd();
    l_poll_fd.events = POLLIN;

    while (true) {
        if (m_shutdown.load()) {
            break;
        }

        const int l_ret = poll(&l_poll_fd, 1, 1000);

        if (l_ret < 0) {
            m_log->error("poll() error {}", strerror(errno));

            break;
        } else if (l_ret == 0) {
            continue;
        }

        p_nfq->step();
    }

    m_log->trace("ebpfsnitch_daemon::filter_thread() exit");
}

void
ebpfsnitch_daemon::probe_thread()
{
    m_log->trace("ebpfsnitch_daemon::probe_thread() entry");

    while (!m_shutdown.load()) {
        m_ring_buffer->poll(100);
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

    const std::shared_ptr<process_info_t> l_process_info =
        m_process_manager.lookup_process_info(l_info->m_process_id);

    if (l_process_info == nullptr) {
        m_log->error("process does not exist {}", l_info->m_process_id);

        return;
    }

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
    l_info2.m_executable = l_process_info->m_executable;
    l_info2.m_container  = l_process_info->m_container_id.value_or("");

    {
        std::lock_guard<std::mutex> l_guard(m_lock);

        m_mapping[l_key] = l_info2;
    }

    process_unassociated();
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
ebpfsnitch_daemon::nfq_handler(const struct nlmsghdr *const p_header)
{
    struct nlattr *l_attributes[NFQA_MAX + 1] = {};
    
    if (nfq_nlmsg_parse(p_header, l_attributes) < 0) {
        m_log->error("nfq_nlmsg_parse() failed");

        return MNL_CB_ERROR;
    }

    if (l_attributes[NFQA_PACKET_HDR] == NULL) {
        m_log->error("l_attributes[NFQA_PACKET_HDR] failed");

        return MNL_CB_ERROR;
    }

    struct nfgenmsg *const l_nfgen_message = (struct nfgenmsg *)
        mnl_nlmsg_get_payload(p_header);

    struct nfqnl_msg_packet_hdr *const l_packet_header =
        (struct nfqnl_msg_packet_hdr *)
        mnl_attr_get_payload(l_attributes[NFQA_PACKET_HDR]);

    const uint16_t l_payload_length =
        mnl_attr_get_payload_len(l_attributes[NFQA_PAYLOAD]);

    const char *const l_data = (char *)
        mnl_attr_get_payload(l_attributes[NFQA_PAYLOAD]);

    const uint32_t l_packet_id = ntohl(l_packet_header->packet_id);

    if (l_payload_length < 24) {
        m_log->error("unknown dropping malformed");

        set_verdict(l_packet_id, NF_DROP);

        return MNL_CB_OK;
    }

    const ip_protocol_t l_proto =
        static_cast<ip_protocol_t>(*((uint8_t*) (l_data + 9)));

    struct nfq_event_t l_nfq_event;

    l_nfq_event.m_nfq_id              = l_packet_id;
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

    /*
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
    */

    process_nfq_event(l_nfq_event, true);

    return MNL_CB_OK;
}

const char *
dns_validate_qname(const char *const buffer)
{
    const char *iter = buffer;

    while (true) {
        const uint8_t byte = *iter; iter++;

        if (byte == 0) {
            return iter;
        } else if (byte > 63) {
            std::cout << "got compression" << std::endl;
            return NULL;
        }

        iter += byte;
    }

    return iter;
}

int
ebpfsnitch_daemon::nfq_handler_incoming(const struct nlmsghdr *const p_header)
{
    struct nlattr *l_attributes[NFQA_MAX + 1] = {};
    
    if (nfq_nlmsg_parse(p_header, l_attributes) < 0) {
        m_log->error("nfq_nlmsg_parse() failed");

        return MNL_CB_ERROR;
    }

    if (l_attributes[NFQA_PACKET_HDR] == NULL) {
        m_log->error("l_attributes[NFQA_PACKET_HDR] failed");

        return MNL_CB_ERROR;
    }

    struct nfgenmsg *const l_nfgen_message = (struct nfgenmsg *)
        mnl_nlmsg_get_payload(p_header);

    struct nfqnl_msg_packet_hdr *const l_packet_header =
        (struct nfqnl_msg_packet_hdr *)
        mnl_attr_get_payload(l_attributes[NFQA_PACKET_HDR]);

    const uint16_t l_payload_length =
        mnl_attr_get_payload_len(l_attributes[NFQA_PAYLOAD]);

    const char *const l_data = (char *)
        mnl_attr_get_payload(l_attributes[NFQA_PAYLOAD]);

    const uint32_t l_packet_id = ntohl(l_packet_header->packet_id);

    if (l_payload_length < 24) {
        m_log->error("unknown dropping malformed");

        m_nfq_incoming->send_verdict(l_packet_id, NF_DROP);

        return MNL_CB_OK;
    }

    const ip_protocol_t l_proto =
        static_cast<ip_protocol_t>(*((uint8_t*) (l_data + 9)));

    struct nfq_event_t l_nfq_event;

    l_nfq_event.m_nfq_id              = l_packet_id;
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

    if (l_proto == ip_protocol_t::UDP) {
        m_log->info(
            "incoming packet {} source {}:{}, destination {}:{} len {}",
            ip_protocol_to_string(l_proto),
            ipv4_to_string(l_nfq_event.m_source_address),
            l_nfq_event.m_source_port,
            ipv4_to_string(l_nfq_event.m_destination_address),
            l_nfq_event.m_destination_port,
            l_payload_length
        );
    }

    if (l_nfq_event.m_source_port == 53) {
        process_dns(l_data + 28, l_data + l_payload_length);
    }

    m_nfq_incoming->send_verdict(l_packet_id, NF_ACCEPT);

    return MNL_CB_OK;
}

void
ebpfsnitch_daemon::process_dns(
    const char *const l_dns_start,
    const char *const l_dns_end
){
    if (l_dns_start + 12 > l_dns_end) {
        m_log->warn("dns less than header size");

        return;
    }

    const uint16_t l_questions  = dns_get_question_count(l_dns_start);
    const uint16_t l_answers    = dns_get_answer_count(l_dns_start);
    const uint16_t l_authority  = dns_get_authority_count(l_dns_start);
    const uint16_t l_additional = dns_get_additional_count(l_dns_start);
    
    m_log->info(
        "{} {} {} {}",
        l_questions,
        l_answers,
        l_authority,
        l_additional
    );

    if (l_questions != 1) {
        m_log->warn("dns got {} questions, ignoring", l_questions);

        return;
    }

    if (l_answers == 0) {
        m_log->warn("dns got {} answers, ignoring", l_answers);

        return;
    }

    const char *l_iter = dns_get_body(l_dns_start);

    struct dns_question_t l_question;

    l_iter = dns_get_question(l_iter, &l_question, l_dns_end);

    if (l_iter == NULL) {
        m_log->warn("failed to get question");

        return;
    }

    for (uint l_i = 0; l_i < l_answers; l_i++) {
        struct dns_resource_record_t l_resource;

        l_iter = dns_get_record(l_iter, &l_resource, l_dns_end);

        if (l_iter == NULL) {
            m_log->warn("failed to get resource record");

            return;
        }

        if (l_resource.m_type != 1) {
            m_log->warn("not A record, ignoring");

            return;
        }

        if (l_resource.m_data_length != 4) {
            m_log->warn("record length expected 4 bytes");

            return;
        }

        const uint32_t l_address = *((uint32_t *)l_resource.m_data);

        m_log->info(
            "Got A record for {} {}",
            dns_decode_qname(l_question.m_name),
            ipv4_to_string(l_address)
        );

        std::lock_guard<std::mutex> l_guard(m_reverse_dns_lock);
        m_reverse_dns[l_address] = dns_decode_qname(l_question.m_name);
    }    
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
            
            const int l_ret = poll(&l_poll_fd, 1, 1000);

            if (l_ret < 0) {
                m_log->error("poll() unix socket error {}", l_ret);

                break;
            } else if (l_ret == 0) {
                continue;
            }

            const int l_client_fd = accept(
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

    line_reader l_reader(p_sock);

    bool l_awaiting_action = false;

    {
        m_log->info("sending initial ruleset to ui");

        const nlohmann::json l_json = {
            { "kind",   "setRules"                    },
            { "rules",  m_rule_engine.rules_to_json() }
        };

        const std::string l_json_serialized = l_json.dump() + "\n";
        writeAll(p_sock, l_json_serialized);
    }

    auto l_last_ping = std::chrono::system_clock::now();

    struct pollfd l_poll_fd;
    l_poll_fd.fd     = p_sock;
    l_poll_fd.events = POLLIN;

    while (true) {
        if (m_shutdown.load()) {
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

            const std::string l_json_serialized = l_json.dump() + "\n";

            writeAll(p_sock, l_json_serialized);

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

                    const std::string l_json_serialized = l_json.dump() + "\n";

                    writeAll(p_sock, l_json_serialized);
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

        const std::string l_domain =
            lookup_domain(l_nfq_event.m_destination_address)
                .value_or("");

        const nlohmann::json l_json = {
            { "kind",               "query"                        },
            { "executable",         l_info.m_executable            },
            { "userId",             l_info.m_user_id               },
            { "processId",          l_info.m_process_id            },
            { "sourceAddress",
                ipv4_to_string(l_nfq_event.m_source_address)       },
            { "sourcePort",         l_nfq_event.m_source_port      },
            { "destinationPort",    l_nfq_event.m_destination_port },
            { "destinationAddress",
                ipv4_to_string(l_nfq_event.m_destination_address)  },
            { "container",          l_info.m_container             },
            { "protocol",
                ip_protocol_to_string(l_nfq_event.m_protocol)      },
            { "domain",             l_domain                       }
        };

        const std::string l_json_serialized = l_json.dump() + "\n";

        writeAll(p_sock, l_json_serialized);

        l_awaiting_action = true;
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

    m_nfq->send_verdict(p_id, p_verdict);
}

std::optional<std::string>
ebpfsnitch_daemon::lookup_domain(const uint32_t p_address)
{
    std::lock_guard<std::mutex> l_guard(m_reverse_dns_lock);

    const auto l_iter = m_reverse_dns.find(p_address);

    if (l_iter != m_reverse_dns.end()) {
        return std::optional<std::string>(l_iter->second);
    } else {
        return std::nullopt;
    }
}