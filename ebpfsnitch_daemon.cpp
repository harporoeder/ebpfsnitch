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
#include "probes_compiled.h"

iptables_raii::iptables_raii(std::shared_ptr<spdlog::logger> p_log):
    m_log(p_log)
{
    m_log->trace("adding iptables rules");

    ::std::system(
        "iptables --append OUTPUT --table mangle --match conntrack "
        "--ctstate NEW,RELATED "
        "--jump NFQUEUE --queue-num 0"
    );

    ::std::system(
        "ip6tables --append OUTPUT --table mangle --match conntrack "
        "--ctstate NEW,RELATED "
        "--jump NFQUEUE --queue-num 2"
    );

    ::std::system("iptables --append INPUT --jump NFQUEUE --queue-num 1");

    ::std::system(
        "iptables --insert DOCKER-USER "
        "--match conntrack --ctstate NEW,RELATED "
        "--jump NFQUEUE --queue-num 0"
    );

    ::std::system("conntrack --flush");
}

iptables_raii::~iptables_raii()
{
    m_log->trace("removing iptables rules");

    remove_rules();
}

void
iptables_raii::remove_rules()
{
    ::std::system(
        "iptables --delete OUTPUT --table mangle --match conntrack "
        "--ctstate NEW,RELATED "
        "--jump NFQUEUE --queue-num 0"
    );

    ::std::system(
        "ip6tables --delete OUTPUT --table mangle --match conntrack "
        "--ctstate NEW,RELATED "
        "--jump NFQUEUE --queue-num 2"
    );

    ::std::system("iptables --delete INPUT --jump NFQUEUE --queue-num 1");

    ::std::system(
        "iptables --delete DOCKER-USER "
        "--match conntrack --ctstate NEW,RELATED "
        "--jump NFQUEUE --queue-num 0"
    );
}

ebpfsnitch_daemon::ebpfsnitch_daemon(
    std::shared_ptr<spdlog::logger> p_log,
    std::optional<std::string>      p_group,
    std::optional<std::string>      p_rules_path
):
    m_rule_engine(p_rules_path.value_or("rules.json")),
    m_log(p_log),
    m_group(p_group),
    m_shutdown(false),
    m_bpf_wrapper(
        p_log,
        std::string(
            reinterpret_cast<char*>(probes_c_o), sizeof(probes_c_o)
        )
    ),
    m_process_manager(p_log)
{
    m_log->trace("ebpfsnitch_daemon constructor");
    
    m_log->trace("setting up ebpf");

    m_bpf_wrapper.attach_kprobe(
        "kprobe_security_socket_send_msg",
        "security_socket_sendmsg",
        false
    );

    m_bpf_wrapper.attach_kprobe(
        "kretprobe_security_socket_send_msg",
        "security_socket_sendmsg",
        true
    );

    m_bpf_wrapper.attach_kprobe(
        "kprobe_tcp_v4_connect",
        "tcp_v4_connect",
        false
    );

    m_bpf_wrapper.attach_kprobe(
        "kretprobe_tcp_v4_connect",
        "tcp_v4_connect",
        true
    );

    m_bpf_wrapper.attach_kprobe(
        "kprobe_tcp_v6_connect",
        "tcp_v6_connect",
        false
    );

    m_bpf_wrapper.attach_kprobe(
        "kretprobe_tcp_v6_connect",
        "tcp_v6_connect",
        true
    );

    m_ring_buffer = std::make_shared<bpf_wrapper_ring>(
        m_bpf_wrapper.lookup_map_fd_by_name("g_probe_ipv4_events"),
        ::std::bind(
            &ebpfsnitch_daemon::bpf_reader,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        )
    );

    m_nfq = std::make_shared<nfq_wrapper>(
        0,
        ::std::bind(
            &ebpfsnitch_daemon::nfq_handler,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        ),
        address_family_t::INET
    );

    m_nfqv6 = std::make_shared<nfq_wrapper>(
        2,
        ::std::bind(
            &ebpfsnitch_daemon::nfq_handler,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        ),
        address_family_t::INET6
    );

    m_nfq_incoming = std::make_shared<nfq_wrapper>(
        1,
        ::std::bind(
            &ebpfsnitch_daemon::nfq_handler_incoming,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        ),
        address_family_t::INET
    );

    m_iptables_raii = std::make_unique<iptables_raii>(p_log);

    m_thread_group.push_back(
        ::std::thread(&ebpfsnitch_daemon::filter_thread, this, m_nfq)
    );

    m_thread_group.push_back(
        ::std::thread(&ebpfsnitch_daemon::filter_thread, this, m_nfqv6)
    );

    m_thread_group.push_back(
        ::std::thread(&ebpfsnitch_daemon::filter_thread, this, m_nfq_incoming)
    );

    m_thread_group.push_back(
        ::std::thread(&ebpfsnitch_daemon::probe_thread, this)
    );

    m_thread_group.push_back(
        ::std::thread(&ebpfsnitch_daemon::control_thread, this)
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
    (void)p_data_size;

    const struct probe_ipv4_event_t *const l_info =
        static_cast<probe_ipv4_event_t *>(p_data);

    const uint16_t l_source_port      = l_info->m_source_port;
    const uint16_t l_destination_port = ntohs(l_info->m_destination_port);

    const std::string l_destination_address = [&]() {
        if (l_info->m_v6) {
            return ipv6_to_string(l_info->m_destination_address_v6);
        } else {
            return ipv4_to_string(l_info->m_destination_address);
        }
    }();

    const std::string l_source_address = [&]() {
        if (l_info->m_v6) {
            return ipv6_to_string(l_info->m_source_address_v6);
        } else {
            return ipv4_to_string(l_info->m_source_address);
        }
    }();

    const std::shared_ptr<const process_info_t> l_process_info =
        m_process_manager.lookup_process_info(l_info->m_process_id);

    if (l_process_info == nullptr) {
        m_log->error("process does not exist {}", l_info->m_process_id);

        return;
    }

    // sanity check compare expected properties
    if (l_info->m_user_id != l_process_info->m_user_id) {
        m_log->error("ebpf and proc mismatch userid");

        return;
    }

    const std::string l_key =
        l_source_address +
        std::to_string(l_source_port) +
        l_destination_address +
        std::to_string(l_destination_port);

    if (l_info->m_v6) {
        m_log->info("setting key to {}", l_key);
    }

    {
        std::lock_guard<std::mutex> l_guard(m_lock);

        m_mapping[l_key] = l_process_info;
    }

    process_unassociated();
}

bool
ebpfsnitch_daemon::process_associated_event(
    const struct nfq_event_t    &l_nfq_event,
    const struct process_info_t &l_info
) {
    const std::optional<bool> l_verdict = m_rule_engine.get_verdict(
        l_nfq_event,
        l_info
    );

    if (l_verdict) {
        if (l_verdict.value()) {
            l_nfq_event.m_queue->send_verdict(l_nfq_event.m_nfq_id, NF_ACCEPT);

            return true;
        } else {
            l_nfq_event.m_queue->send_verdict(l_nfq_event.m_nfq_id, NF_DROP);

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
    const std::shared_ptr<const struct process_info_t> l_optional_info =
        lookup_connection_info(l_nfq_event);

    if (l_optional_info) {
        if (process_associated_event(l_nfq_event, *l_optional_info)) {
            return true;
        }
    }

    if (p_queue_unassociated) {
        if (l_optional_info) {
            std::lock_guard<std::mutex> l_guard(m_undecided_packets_lock);
            m_undecided_packets.push(l_nfq_event);

        } else {
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
    nfq_wrapper *const           p_queue,
    const struct nlmsghdr *const p_header
) {
    assert(p_queue);
    assert(p_header);

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

        p_queue->send_verdict(l_packet_id, NF_DROP);

        return MNL_CB_OK;
    }

    const uint8_t l_ip_version = (*l_data & 0b11110000) >> 4;

    if (l_ip_version != 4 && l_ip_version != 6) {
        m_log->warn("got unknown ip protocol version {}", l_ip_version);

        p_queue->send_verdict(l_packet_id, NF_DROP);

        return MNL_CB_OK;
    }

    struct nfq_event_t l_nfq_event = {
        .m_v6        = l_ip_version == 6,
        .m_user_id   = 0,
        .m_group_id  = 0,
        .m_nfq_id    = l_packet_id,
        .m_timestamp = nanoseconds(),
        .m_queue     = p_queue
    };

    if (l_ip_version == 4) {
        l_nfq_event.m_source_address      = *((uint32_t*) (l_data + 12));
        l_nfq_event.m_destination_address = *((uint32_t*) (l_data + 16));
        l_nfq_event.m_protocol            =
            static_cast<ip_protocol_t>(*((uint8_t*) (l_data + 9)));
    } else {
        l_nfq_event.m_source_address_v6      = *((__uint128_t*) (l_data + 8));
        l_nfq_event.m_destination_address_v6 = *((__uint128_t*) (l_data + 24));
        l_nfq_event.m_protocol               =
            static_cast<ip_protocol_t>(*((uint8_t*) (l_data + 6)));
    }

    const char *const l_ip_body =
        (l_ip_version == 6) ? (l_data + 40) : (l_data + 20);

    if (
        l_nfq_event.m_protocol == ip_protocol_t::TCP ||
        l_nfq_event.m_protocol == ip_protocol_t::UDP
    ) {
        l_nfq_event.m_source_port      = ntohs(*((uint16_t*) l_ip_body));
        l_nfq_event.m_destination_port = ntohs(*((uint16_t*) (l_ip_body + 2)));
    }  else {
        l_nfq_event.m_source_port      = 0;
        l_nfq_event.m_destination_port = 0;
    }

    if (l_ip_version == 6) {
        m_log->info(
            "nfq_handler ipv6 [{}]:{} [{}]:{}",
            ipv6_to_string(l_nfq_event.m_source_address_v6),
            l_nfq_event.m_source_port,
            ipv6_to_string(l_nfq_event.m_destination_address_v6),
            l_nfq_event.m_destination_port
        );
    }

    process_nfq_event(l_nfq_event, true);

    return MNL_CB_OK;
}

int
ebpfsnitch_daemon::nfq_handler_incoming(
    nfq_wrapper *const           p_queue,
    const struct nlmsghdr *const p_header
) {
    assert(p_queue);
    assert(p_header);

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

        p_queue->send_verdict(l_packet_id, NF_DROP);

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
    l_nfq_event.m_queue               = p_queue;
    
    if (l_proto == ip_protocol_t::TCP || l_proto == ip_protocol_t::UDP) {
        l_nfq_event.m_source_port      = ntohs(*((uint16_t*) (l_data + 20)));
        l_nfq_event.m_destination_port = ntohs(*((uint16_t*) (l_data + 22)));
    } else {
        l_nfq_event.m_source_port      = 0;
        l_nfq_event.m_destination_port = 0;
    }

    if (l_proto == ip_protocol_t::UDP) {
        if (l_nfq_event.m_source_port == 53) {
            process_dns(l_data + 28, l_data + l_payload_length);
        }
    }

    m_nfq_incoming->send_verdict(l_packet_id, NF_ACCEPT);

    return MNL_CB_OK;
}

void
ebpfsnitch_daemon::process_dns(
    const char *const p_packet,
    const char *const l_dns_end
){
    const size_t l_packet_size = l_dns_end - p_packet;

    struct dns_header_t l_header;

    if (!dns_parse_header(p_packet, l_packet_size, &l_header)) {
        m_log->warn("dns_parse_header() failed");

        return;
    }

    if (l_header.m_question_count != 1) {
        m_log->warn(
            "dns got {} questions, ignoring",
            l_header.m_question_count
        );

        return;
    }

    if (l_header.m_answer_count == 0) {
        m_log->warn("dns got {} answers, ignoring", l_header.m_answer_count);

        return;
    }

    const char *l_iter = dns_get_body(p_packet);

    struct dns_question_t l_question;

    l_iter = dns_parse_question(p_packet, l_packet_size, l_iter, &l_question);

    if (l_iter == NULL) {
        m_log->warn("dns_parse_question() failed");

        return;
    }

    const std::optional l_question_name = dns_decode_qname(
        p_packet, l_packet_size, l_question.m_name, true
    );

    if (!l_question_name) {
        m_log->warn("dns_decode_qname() for question failed");

        return;
    }

    for (uint l_i = 0; l_i < l_header.m_answer_count; l_i++) {
        struct dns_resource_record_t l_resource;

        l_iter = dns_parse_record(p_packet, l_packet_size, l_iter, &l_resource);

        if (l_iter == NULL) {
            m_log->warn("dns_parse_record() failed");

            return;
        }

        if (l_resource.m_type != 1) {
            return;
        }

        if (l_resource.m_data_length != 4) {
            m_log->warn("record length A expected 4 bytes");

            return;
        }

        const uint32_t l_address = *((uint32_t *)l_resource.m_data);

        const std::optional l_record_name = dns_decode_qname(
            p_packet, l_packet_size, l_resource.m_name, true
        );

        if (!l_record_name) {
            m_log->warn("dns_decode_qname() for record failed");
    
            return;
        }

        m_log->info(
            "Got A record for {} {} {}",
            l_question_name.value(),
            l_record_name.value(),
            ipv4_to_string(l_address)
        );

        std::lock_guard<std::mutex> l_guard(m_reverse_dns_lock);
        m_reverse_dns[l_address] = l_question_name.value();
    }    
}

std::shared_ptr<const struct process_info_t>
ebpfsnitch_daemon::lookup_connection_info(const nfq_event_t &p_event)
{
    const std::string l_key =
        !p_event.m_v6 ?
            ipv4_to_string(p_event.m_source_address) +
            std::to_string(p_event.m_source_port) +
            ipv4_to_string(p_event.m_destination_address) +
            std::to_string(p_event.m_destination_port)
        :
            ipv6_to_string(p_event.m_source_address_v6) +
            std::to_string(p_event.m_source_port) +
            ipv6_to_string(p_event.m_destination_address_v6) +
            std::to_string(p_event.m_destination_port);

    if (p_event.m_v6) {
        m_log->info("looking up key {}", l_key);
    }

    std::lock_guard<std::mutex> l_guard(m_lock);

    if (m_mapping.find(l_key) != m_mapping.end()) {
        return m_mapping[l_key];
    } else {
        const std::string l_key2 =
            !p_event.m_v6 ?
                "0.0.0.0" +
                std::to_string(p_event.m_source_port) +
                ipv4_to_string(p_event.m_destination_address) +
                std::to_string(p_event.m_destination_port)
            :
                "::" +
                std::to_string(p_event.m_source_port) +
                ipv6_to_string(p_event.m_destination_address_v6) +
                std::to_string(p_event.m_destination_port);
        
        if (m_mapping.find(l_key2) != m_mapping.end()) {
            return m_mapping[l_key2];
        }

        return nullptr;
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

        const std::shared_ptr<const struct process_info_t> l_info =
            lookup_connection_info(l_nfq_event);

        if (!l_info) {
            m_log->error("handle_control has no connection info");

            l_nfq_event.m_queue->send_verdict(l_nfq_event.m_nfq_id, NF_DROP);

            std::lock_guard<std::mutex> l_guard(m_undecided_packets_lock);
            m_undecided_packets.pop();

            continue;
        }

        const std::string l_domain =
            lookup_domain(l_nfq_event.m_destination_address)
                .value_or("");

        const nlohmann::json l_json = {
            { "kind",               "query"                        },
            { "executable",         l_info->m_executable           },
            { "userId",             l_info->m_user_id              },
            { "processId",          l_info->m_process_id           },
            { "sourceAddress",
                ipv4_to_string(l_nfq_event.m_source_address)       },
            { "sourcePort",         l_nfq_event.m_source_port      },
            { "destinationPort",    l_nfq_event.m_destination_port },
            { "destinationAddress",
                ipv4_to_string(l_nfq_event.m_destination_address)  },
            { "container",
                l_info->m_container_id.value_or("")                },
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

        std::shared_ptr<const struct process_info_t> l_info =
            lookup_connection_info(l_nfq_event);

        if (l_info) {
            if (!process_associated_event(l_nfq_event, *l_info)) {
                std::lock_guard<std::mutex> l_guard2(
                    m_undecided_packets_lock
                );

                m_undecided_packets.push(l_nfq_event);
            }
        } else {
            // two seconds
            if (nanoseconds() > (l_nfq_event.m_timestamp + 2000000000 )) {
                /*
                m_log->error(
                    "dropping still unassociated {}",
                    nfq_event_to_string(l_nfq_event)
                );
                */

                l_nfq_event.m_queue->send_verdict(l_nfq_event.m_nfq_id, NF_DROP);
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

        const std::shared_ptr<const struct process_info_t> l_info =
            lookup_connection_info(l_unhandled);

        if (l_info) {
            if (!process_associated_event(l_unhandled, *l_info)) {
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