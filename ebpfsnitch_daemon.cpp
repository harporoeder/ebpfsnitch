#include <unistd.h>
#include <string>
#include <unistd.h>
#include <netinet/in.h>
#include <thread>
#include <arpa/inet.h>
#include <unordered_map>
#include <mutex>
#include <assert.h>
#include <poll.h>
#include <sys/un.h>
#include <nlohmann/json.hpp>
#include <exception>
#include <sys/select.h>
#include <string.h>

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

    ::std::system("ip6tables --append INPUT --jump NFQUEUE --queue-num 3");

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

    ::std::system("ip6tables --delete INPUT --jump NFQUEUE --queue-num 3");

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
    m_process_manager(p_log),
    m_bpf_wrapper(
        p_log,
        std::string(
            reinterpret_cast<char*>(probes_c_o), sizeof(probes_c_o)
        )
    )
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
            std::placeholders::_2,
            std::placeholders::_3
        ),
        address_family_t::INET
    );

    m_nfqv6 = std::make_shared<nfq_wrapper>(
        2,
        ::std::bind(
            &ebpfsnitch_daemon::nfq_handler,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3
        ),
        address_family_t::INET6
    );

    m_nfq_incoming = std::make_shared<nfq_wrapper>(
        1,
        ::std::bind(
            &ebpfsnitch_daemon::nfq_handler_incoming,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3
        ),
        address_family_t::INET
    );

    m_nfq_incomingv6 = std::make_shared<nfq_wrapper>(
        3,
        ::std::bind(
            &ebpfsnitch_daemon::nfq_handler_incoming,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3
        ),
        address_family_t::INET6
    );

    m_iptables_raii = std::make_unique<iptables_raii>(p_log);

    m_control_api = std::make_shared<control_api>(
        p_log,
        p_group,
        [this](std::shared_ptr<control_api::session> p_session) {
            m_log->info("on_connect_cb");

            p_session->queue_outgoing_json({
                { "kind",  "setRules"                         },
                { "rules", m_rule_engine.rules_to_json(false) }
            });

            p_session->queue_outgoing_json({
                { "kind",     "setProcesses"                         },
                { "processes", m_process_manager.processes_to_json() }
            });

            std::shared_ptr<connection_context> l_context =
                std::make_shared<connection_context>();

            l_context->m_pending_verdict = false;
            l_context->m_session         = p_session;

            std::weak_ptr<connection_context> l_context_weak = l_context;

            p_session->set_on_message_cb(
                std::bind(
                    &ebpfsnitch_daemon::handle_control_message,
                    this,
                    l_context_weak,
                    std::placeholders::_1
                )
            );

            p_session->set_on_disconnect_cb(
                std::bind(
                    &ebpfsnitch_daemon::handle_disconnect,
                    this,
                    l_context_weak
                )
            );

            {
                std::lock_guard<std::mutex> l_guard(m_control_connections_lock);
                m_control_connections.insert(l_context);
            }

            process_unhandled();
        }
    );

    m_process_manager.set_load_process_cb(
        [&] (const process_info_t &p_process) {
            nlohmann::json l_json = {
                { "kind",       "addProcess"           },
                { "processId" , p_process.m_process_id },
                { "executable", p_process.m_executable },
                { "userId",     p_process.m_user_id    },
                { "groupId",    p_process.m_group_id   }
            };

            send_to_all_control_connections(l_json);
        }
    );

    m_process_manager.set_remove_process_cb(
        [&] (const uint32_t p_process_id) {
            nlohmann::json l_json = {
                { "kind",       "removeProcess" },
                { "processId" , p_process_id    }
            };

            send_to_all_control_connections(l_json);
        }
    );

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
        ::std::thread(&ebpfsnitch_daemon::filter_thread, this, m_nfq_incomingv6)
    );

    m_thread_group.push_back(
        ::std::thread(&ebpfsnitch_daemon::probe_thread, this)
    );
}

ebpfsnitch_daemon::~ebpfsnitch_daemon()
{
    m_log->trace("ebpfsnitch_daemon destructor");

    shutdown();

    for (auto &l_thread : m_thread_group) {
        l_thread.join();
    }
}

void
ebpfsnitch_daemon::filter_thread(std::shared_ptr<nfq_wrapper> p_nfq)
{
    m_log->trace("ebpfsnitch_daemon::filter_thread() entry");

    try {
        fd_set l_fd_set;

        const int l_stop_fd = m_stopper.get_stop_fd();
        const int l_nfq_fd  = p_nfq->get_fd();
        const int l_max_fd  = std::max(l_stop_fd, l_nfq_fd);

        while (true) {
            FD_ZERO(&l_fd_set);
            FD_SET(l_stop_fd, &l_fd_set);
            FD_SET(l_nfq_fd, &l_fd_set);

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
            } else if (FD_ISSET(l_nfq_fd, &l_fd_set)) {
                p_nfq->step();
            } else {
                m_log->error("filter_thread() select() unknown fd");

                break;
            }
        }
    } catch (const std::exception &p_err) {
        m_log->error("filter_thread() exception {}", p_err.what());
    }

    m_stopper.stop();

    m_log->trace("ebpfsnitch_daemon::filter_thread() exit");
}

void
ebpfsnitch_daemon::probe_thread()
{
    m_log->trace("ebpfsnitch_daemon::probe_thread() entry");

    try {
        fd_set l_fd_set;

        const int l_stop_fd = m_stopper.get_stop_fd();
        const int l_ring_fd = m_ring_buffer->get_fd();
        const int l_max_fd  = std::max(l_stop_fd, l_ring_fd);

        while (true) {
            FD_ZERO(&l_fd_set);
            FD_SET(l_stop_fd, &l_fd_set);
            FD_SET(l_ring_fd, &l_fd_set);

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
            } else if (FD_ISSET(l_ring_fd, &l_fd_set)) {
                m_ring_buffer->consume();
            } else {
                m_log->error("probe_thread() select() unknown fd");

                break;
            }
        }
    } catch (const std::exception &p_err) {
        m_log->error("probe_thread() exception {}", p_err.what());
    }

    m_stopper.stop();

    m_log->trace("ebpfsnitch_daemon::probe_thread() exit");
}

void
ebpfsnitch_daemon::bpf_reader(
    void *const p_data,
    const int   p_data_size
){
    assert(p_data);
    assert(p_data_size == sizeof(ebpf_event_t));

    const struct ebpf_event_t *const l_info =
        static_cast<ebpf_event_t *>(p_data);

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

    struct ebpf_event_t l_info2;
    memcpy(&l_info2, l_info, sizeof(ebpf_event_t));
    l_info2.m_destination_port = ntohs(l_info->m_destination_port);

    /*
    m_log->trace(
        "got bpf event {} src {}:{} dst {}:{}",
        ip_protocol_to_string(static_cast<ip_protocol_t>(l_info2.m_protocol)),
        ipv4_to_string(l_info2.m_source_address),
        std::to_string(l_info2.m_source_port),
        ipv4_to_string(l_info2.m_destination_address),
        std::to_string(l_info2.m_destination_port)
    );
    */

    m_connection_manager.add_connection_info(l_info2, l_process_info);

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
            l_nfq_event.m_queue->send_verdict(
                l_nfq_event.m_nfq_id,
                nfq_verdict_t::ACCEPT
            );

            return true;
        } else {
            l_nfq_event.m_queue->send_verdict(
                l_nfq_event.m_nfq_id,
                nfq_verdict_t::DROP
            );

            return true;
        }
    }

    return false;
}

void
ebpfsnitch_daemon::ask_verdict(
    const std::shared_ptr<const struct process_info_t> l_info,
    const struct nfq_event_t                          &l_nfq_event
) {
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

    std::lock_guard<std::mutex> l_guard(m_control_connections_lock);

    for (const auto &l_context: m_control_connections) {
        if (l_context->m_pending_verdict == false) {
            l_context->m_session->queue_outgoing_json(l_json);
            l_context->m_pending_verdict = true;
        }
    }
}

bool
ebpfsnitch_daemon::process_nfq_event(
    const struct nfq_event_t &l_nfq_event,
    const bool                p_queue_unassociated
) {
    const std::shared_ptr<const struct process_info_t> l_info =
        m_connection_manager.lookup_connection_info(l_nfq_event);

    if (l_info) {
        if (process_associated_event(l_nfq_event, *l_info)) {
            return true;
        }
    }

    if (p_queue_unassociated) {
        if (l_info) {
            {
                std::lock_guard<std::mutex> l_guard(m_undecided_packets_lock);

                m_undecided_packets.push(l_nfq_event);
            }

            process_unhandled();
        } else {
            std::lock_guard<std::mutex> l_guard(
                m_unassociated_packets_lock
            );

            m_unassociated_packets.push(l_nfq_event);
        }
    }

    return false;
}

nfq_cb_result_t
ebpfsnitch_daemon::nfq_handler(
    nfq_wrapper *const                p_queue,
    const uint32_t                    p_packet_id,
    const std::span<const std::byte> &p_packet
) {
    assert(p_queue);

    const uint16_t    l_payload_length = p_packet.size();
    const char *const l_data           = (char *)p_packet.data();

    if (l_payload_length < 24) {
        m_log->error("unknown dropping malformed");

        p_queue->send_verdict(p_packet_id, nfq_verdict_t::DROP);

        return nfq_cb_result_t::OK;
    }

    const uint8_t l_ip_version = (*l_data & 0b11110000) >> 4;

    if (l_ip_version != 4 && l_ip_version != 6) {
        m_log->warn("got unknown ip protocol version {}", l_ip_version);

        p_queue->send_verdict(p_packet_id, nfq_verdict_t::DROP);

        return nfq_cb_result_t::OK;
    }

    struct nfq_event_t l_nfq_event = {
        .m_v6        = l_ip_version == 6,
        .m_user_id   = 0,
        .m_group_id  = 0,
        .m_nfq_id    = p_packet_id,
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

    process_nfq_event(l_nfq_event, true);

    return nfq_cb_result_t::OK;
}

nfq_cb_result_t
ebpfsnitch_daemon::nfq_handler_incoming(
    nfq_wrapper *const                p_queue,
    const uint32_t                    p_packet_id,
    const std::span<const std::byte> &p_packet
) {
    assert(p_queue);

    const uint16_t    l_payload_length = p_packet.size();
    const char *const l_data           = (char *)p_packet.data();

    if (l_payload_length < 24) {
        m_log->error("unknown dropping malformed");

        p_queue->send_verdict(p_packet_id, nfq_verdict_t::DROP);

        return nfq_cb_result_t::OK;
    }

    const uint8_t l_ip_version = (*l_data & 0b11110000) >> 4;

    if (l_ip_version != 4 && l_ip_version != 6) {
        m_log->warn("got unknown ip protocol version {}", l_ip_version);

        p_queue->send_verdict(p_packet_id, nfq_verdict_t::DROP);

        return nfq_cb_result_t::OK;
    }
    
    const ip_protocol_t l_proto = l_ip_version == 6
        ? static_cast<ip_protocol_t>(*((uint8_t*) (l_data + 6)))
        : static_cast<ip_protocol_t>(*((uint8_t*) (l_data + 9)));

    if (l_proto == ip_protocol_t::UDP) {
        const char *const l_ip_body =
            (l_ip_version == 6) ? (l_data + 40) : (l_data + 20);

        const char *const l_udp_body = l_ip_body + 8;

        if (ntohs(*((uint16_t*) l_ip_body)) == 53) {
            process_dns(l_udp_body, l_data + l_payload_length);
        }
    }

    p_queue->send_verdict(p_packet_id, nfq_verdict_t::ACCEPT);

    return nfq_cb_result_t::OK;
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

        if (l_resource.m_type == dns_resource_record_type::A) {
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

            m_dns_cache.add_ipv4_mapping(l_address, l_question_name.value());
        } else if (l_resource.m_type == dns_resource_record_type::AAAA) {
            if (l_resource.m_data_length != 16) {
                m_log->warn("record length AAAA expected 16 bytes");

                return;
            }

            const __uint128_t l_address = *((__uint128_t *)l_resource.m_data);

            const std::optional l_record_name = dns_decode_qname(
                p_packet, l_packet_size, l_resource.m_name, true
            );

            if (!l_record_name) {
                m_log->warn("dns_decode_qname() for record failed");
        
                return;
            }

            m_log->info(
                "Got AAAA record for {} {} {}",
                l_question_name.value(),
                l_record_name.value(),
                ipv6_to_string(l_address)
            );

            m_dns_cache.add_ipv6_mapping(l_address, l_question_name.value());
        } else {
            return;
        }
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
            m_connection_manager.lookup_connection_info(l_nfq_event);

        if (l_info) {
            if (!process_associated_event(l_nfq_event, *l_info)) {
                {
                    std::lock_guard<std::mutex> l_guard(
                        m_undecided_packets_lock
                    );

                    m_undecided_packets.push(l_nfq_event);
                }

                process_unhandled();
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

                l_nfq_event.m_queue->send_verdict(
                    l_nfq_event.m_nfq_id,
                    nfq_verdict_t::DROP
                );
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

    std::unique_lock<std::mutex> l_guard(m_undecided_packets_lock);

    while (m_undecided_packets.size()) {
        struct nfq_event_t l_event = m_undecided_packets.front(); 

        const std::shared_ptr<const struct process_info_t> l_info =
            m_connection_manager.lookup_connection_info(l_event);

        if (l_info) {
            if (!process_associated_event(l_event, *l_info)) {
                // m_log->info("still undecided");

                l_remaining.push(l_event);

                ask_verdict(l_info, l_event);
            }
        } else {
            m_log->error("event unassociated when it should be, dropping");
        }

        m_undecided_packets.pop();
    }
    
    m_undecided_packets = l_remaining;
}

void
ebpfsnitch_daemon::handle_control_message(
    std::weak_ptr<connection_context> p_context,
    nlohmann::json                    p_message
) {
    std::shared_ptr<connection_context> l_context = p_context.lock();

    if (!l_context) {
        m_log->error("handle_control_message weak_ptr expired");

        return;
    }

    if (p_message["kind"] == "addRule") {
        m_log->info("adding rule");

        const std::string l_rule_id = m_rule_engine.add_rule(p_message);

        p_message["ruleId"] = l_rule_id;

        const nlohmann::json l_json = {
            { "kind", "addRule" },
            { "body", p_message }
        };

        send_to_all_control_connections(l_json);

        l_context->m_pending_verdict = false;

        process_unhandled();
    } else if (p_message["kind"] == "removeRule") {
        m_log->info("removing rule");

        m_rule_engine.delete_rule(p_message["ruleId"]);
    }
}

void
ebpfsnitch_daemon::handle_disconnect(
    std::weak_ptr<connection_context> p_context
) {
    m_log->info("handle_disconnect");

    std::shared_ptr<connection_context> l_context = p_context.lock();

    if (!l_context) {
        m_log->error("handle_disconnect weak_ptr expired");

        return;
    }

    std::lock_guard<std::mutex> l_guard(m_control_connections_lock);

    m_control_connections.erase(l_context);
}

void
ebpfsnitch_daemon::send_to_all_control_connections(
    const nlohmann::json p_message
) {
    std::lock_guard<std::mutex> l_guard(m_control_connections_lock);

    for (const auto &l_context: m_control_connections) {
        l_context->m_session->queue_outgoing_json(p_message);
    }
}

std::string
nfq_event_to_string(const nfq_event_t &p_event)
{
    return
        " proto "              + ip_protocol_to_string(p_event.m_protocol) +
        " sourceAddress "      + ipv4_to_string(p_event.m_source_address) +
        " sourcePort "         + std::to_string(p_event.m_source_port) +
        " destinationAddress " + ipv4_to_string(p_event.m_destination_address) +
        " destinationPort "    + std::to_string(p_event.m_destination_port) +
        " timestamp "          + std::to_string(p_event.m_timestamp);
}

void
ebpfsnitch_daemon::await_shutdown()
{
    m_stopper.await_stop_block();
}

void
ebpfsnitch_daemon::shutdown()
{
    m_log->trace("ebpfsnitch_daemon::shutdown");;

    m_stopper.stop();
}
