#pragma once

#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <optional>
#include <memory>

#include <spdlog/spdlog.h>

#include "control_api.hpp"
#include "misc.hpp"
#include "rule_engine.hpp"
#include "bpf_wrapper.hpp"
#include "nfq_wrapper.hpp"
#include "process_manager.hpp"
#include "nfq_event.h"
#include "dns_cache.hpp"
#include "stopper.hpp"
#include "ebpf_event.hpp"
#include "connection_manager.hpp"

std::string nfq_event_to_string(const nfq_event_t &p_event);

class iptables_raii {
public:
    iptables_raii(std::shared_ptr<spdlog::logger> p_log);

    ~iptables_raii();

    static void remove_rules();

private:
    std::shared_ptr<spdlog::logger> m_log;
};

class ebpfsnitch_daemon {
public:
    ebpfsnitch_daemon(
        std::shared_ptr<spdlog::logger> p_log,
        std::optional<std::string>      p_group,
        std::optional<std::string>      p_rules_path
    );

    ~ebpfsnitch_daemon();

    void await_shutdown();

    void shutdown();

private:
    rule_engine_t m_rule_engine;

    void filter_thread(std::shared_ptr<nfq_wrapper> p_nfq);
    void probe_thread();

    std::mutex m_response_lock;
    void process_unhandled();

    void
    bpf_reader(
        void *const p_data,
        const int   p_data_size
    );

    nfq_cb_result_t
    nfq_handler(
        nfq_wrapper *const                p_queue,
        const uint32_t                    p_packet_id,
        const std::span<const std::byte> &p_packet
    );

    nfq_cb_result_t
    nfq_handler_incoming(
        nfq_wrapper *const                p_queue,
        const uint32_t                    p_packet_id,
        const std::span<const std::byte> &p_packet
    );

    bool
    process_nfq_event(
        const struct nfq_event_t &l_nfq_event,
        const bool                p_queue_unassociated
    );
    // packets with an application without a user verdict
    std::queue<struct nfq_event_t> m_undecided_packets;
    std::mutex m_undecided_packets_lock;

    // packets not yet associated with an application
    std::queue<struct nfq_event_t> m_unassociated_packets;
    std::mutex m_unassociated_packets_lock;
    void process_unassociated();

    void handle_control_message(nlohmann::json p_message);

    void
    ask_verdict(
        const std::shared_ptr<const struct process_info_t> l_info,
        const struct nfq_event_t                          &l_nfq_event
    );

    std::shared_ptr<bpf_wrapper_ring> m_ring_buffer;
    std::shared_ptr<spdlog::logger>   m_log;
    const std::optional<std::string>  m_group;
    std::shared_ptr<nfq_wrapper>      m_nfq;
    std::shared_ptr<nfq_wrapper>      m_nfqv6;
    std::shared_ptr<nfq_wrapper>      m_nfq_incoming;
    std::shared_ptr<nfq_wrapper>      m_nfq_incomingv6;
    process_manager                   m_process_manager;
    dns_cache                         m_dns_cache;
    connection_manager                m_connection_manager;

    bool
    process_associated_event(
        const struct nfq_event_t    &l_nfq_event,
        const struct process_info_t &l_info
    );

    stopper                        m_stopper;
    bpf_wrapper_object             m_bpf_wrapper;
    std::shared_ptr<control_api>   m_control_api;
    bool                           m_pending_verdict;
    std::unique_ptr<iptables_raii> m_iptables_raii;

    std::vector<std::thread> m_thread_group;

    void
    process_dns(
        const char *const p_start,
        const char *const p_end
    );
};
