#pragma once

#include <mutex>
#include <unordered_map>

#include <bcc/bcc_version.h>
#include <bcc/BPF.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <spdlog/spdlog.h>

struct probe_ipv4_event_t {
    uint32_t m_user_id;
    uint32_t m_process_id;
    uint32_t m_source_address;
    uint16_t m_source_port;
    uint32_t m_destination_address;
    uint16_t m_destination_port;
} __attribute__((packed));

struct connection_info_t {
    uint32_t    m_user_id;
    uint32_t    m_process_id;
    std::string m_executable;
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

    static void
    handle_probe_output(
        void *const p_cb_cookie,
        void *const p_data,
        const int   p_data_size
    );

    static int
    nfq_cb(
        struct nfq_q_handle *const p_qh,
        struct nfgenmsg *const     p_nfmsg,
        struct nfq_data *const     p_nfa,
        void *const                p_data
    );

    std::shared_ptr<spdlog::logger> m_log;
    ebpf::BPF m_bpf;
    ebpf::BPFPerfBuffer *m_perf_buffer;
    struct nfq_handle *m_nfq_handle;
    struct nfq_q_handle *m_nfq_queue;
    int m_nfq_fd;
    std::mutex m_lock;
    std::unordered_map<std::string, struct connection_info_t> m_mapping;
    std::atomic<bool> m_shutdown;
    
    std::thread m_filter_thread;
    std::thread m_probe_thread;
};