#pragma once

#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <optional>
#include <memory>
#include <condition_variable>

#include <bcc/bcc_version.h>
#include <bcc/BPF.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <spdlog/spdlog.h>

extern std::condition_variable g_shutdown;

enum class ip_protocol_t : uint8_t {
    ICMP = 1,
    TCP  = 6,
    UDP  = 17
};

std::string ip_protocol_to_string(const ip_protocol_t p_protocol);

struct probe_ipv4_event_t {
    void    *m_handle;
    bool     m_remove;
    uint32_t m_user_id;
    uint32_t m_process_id;
    uint32_t m_source_address;
    uint16_t m_source_port;
    uint32_t m_destination_address;
    uint16_t m_destination_port;
    uint64_t m_timestamp;
} __attribute__((packed));

struct connection_info_t {
    uint32_t    m_user_id;
    uint32_t    m_process_id;
    std::string m_executable;
};

struct nfq_event_t {
    uint32_t m_user_id;
    uint32_t m_group_id;
    uint32_t m_source_address;
    uint16_t m_source_port;
    uint32_t m_destination_address;
    uint16_t m_destination_port;
    uint32_t m_nfq_id;
    uint8_t  m_protocol;
    uint64_t m_timestamp;
};

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
    static void
    bpf_reader_indirect(
        void *const p_cb_cookie,
        void *const p_data,
        const int   p_data_size
    );

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

    std::shared_ptr<spdlog::logger> m_log;
    ebpf::BPF m_bpf;
    ebpf::BPFPerfBuffer *m_perf_buffer;
    struct nfq_handle *m_nfq_handle;
    struct nfq_q_handle *m_nfq_queue;
    int m_nfq_fd;

    bool
    process_associated_event(
        const struct nfq_event_t       &l_nfq_event,
        const struct connection_info_t &l_info
    );

    std::mutex m_lock;
    std::unordered_map<std::string, struct connection_info_t> m_mapping;
    std::optional<struct connection_info_t>
    lookup_connection_info(const nfq_event_t &p_event);

    std::atomic<bool> m_shutdown;

    std::mutex m_verdicts_lock;
    std::unordered_map<std::string, bool> m_verdicts;
    std::optional<bool> get_verdict(const std::string &p_executable);

    std::shared_ptr<iptables_raii> m_iptables_raii;
    
    std::thread m_filter_thread;
    std::thread m_probe_thread;
    std::thread m_control_thread;
};