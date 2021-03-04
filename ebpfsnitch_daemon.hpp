#pragma once

#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <optional>
#include <memory>
#include <condition_variable>

#include <bpf/libbpf.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include <spdlog/spdlog.h>

#include "misc.hpp"
#include "rule_engine.hpp"
#include "bpf_wrapper.hpp"
#include "nfq_wrapper.hpp"

extern std::condition_variable g_shutdown;

std::string nfq_event_to_string(const nfq_event_t &p_event);

class iptables_raii {
public:
    iptables_raii(std::shared_ptr<spdlog::logger> p_log);

    ~iptables_raii();

private:
    std::shared_ptr<spdlog::logger> m_log;
};

class ebpfsnitch_daemon {
public:
    ebpfsnitch_daemon(
        std::shared_ptr<spdlog::logger> p_log
    );

    ~ebpfsnitch_daemon();

private:
    rule_engine_t m_rule_engine;

    void filter_thread();
    void probe_thread();
    void control_thread();

    void handle_control(const int p_sock);

    std::mutex m_response_lock;
    void process_unhandled();

    void
    bpf_reader(
        void *const p_data,
        const int   p_data_size
    );

    // static wrapper -> bpf_reader
    static int
    bpf_reader_indirect(
        void *const  p_cb_cookie,
        void *const  p_data,
        const size_t p_data_size
    );

    int
    nfq_handler2(const struct nlmsghdr *const p_header);

    int
    nfq_handler(
        struct nfq_q_handle *const p_qh,
        struct nfgenmsg *const     p_nfmsg,
        struct nfq_data *const     p_nfa
    );

    // static wrapper -> nfq_handler
    static int
    nfq_handler_indirect(
        struct nfq_q_handle *const p_qh,
        struct nfgenmsg *const     p_nfmsg,
        struct nfq_data *const     p_nfa,
        void *const                p_data
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

    struct ring_buffer *m_ring_buffer;

    std::shared_ptr<spdlog::logger> m_log;
    struct nfq_handle *m_nfq_handle;
    struct nfq_q_handle *m_nfq_queue;
    int m_nfq_fd;

    std::shared_ptr<nfq_wrapper> m_nfq;

    bool
    process_associated_event(
        const struct nfq_event_t       &l_nfq_event,
        const struct connection_info_t &l_info
    );

    std::mutex m_lock;
    std::unordered_map<std::string, struct connection_info_t> m_mapping;
    std::optional<struct connection_info_t>
    lookup_connection_info(const nfq_event_t &p_event);

    std::optional<process_info_t>
    lookup_process_info(const uint32_t p_process_id);

    std::atomic<bool> m_shutdown;
    bpf_wrapper_object m_bpf_wrapper;

    std::mutex m_verdicts_lock;
    std::unordered_map<std::string, bool> m_verdicts;
    std::optional<bool> get_verdict(
        const struct nfq_event_t       &p_nfq_event,
        const struct connection_info_t &p_info
    );

    std::shared_ptr<iptables_raii> m_iptables_raii;

    void set_verdict(const uint32_t p_id, const uint32_t p_verdict);
    
    std::thread m_filter_thread;
    std::thread m_probe_thread;
    std::thread m_control_thread;
};