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

#include <bcc/bcc_version.h>
#include <bcc/BPF.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "ebpfsnitch_daemon.hpp"

std::string
file_to_string(const std::string &p_path);

std::string
ipv4_to_string(const uint32_t p_address);

ebpfsnitch_daemon::ebpfsnitch_daemon(
    std::shared_ptr<spdlog::logger> p_log
):
m_log(p_log),
m_shutdown(false)
{
    m_log->trace("ebpfsnitch_daemon constructor");
    
    m_log->trace("compiling ebpf probes");
    const ebpf::StatusTuple l_init_res = m_bpf.init(file_to_string("probes.c"));
    if (l_init_res.code() != 0) {
        m_log->error("g_bpf.init() failed, {}", l_init_res.msg());

        throw std::runtime_error("failed to compile eBPF");
    }
    
    m_nfq_handle = nfq_open();
    if (m_nfq_handle == NULL) {
        m_log->error("nfq_open() failed");

        throw std::runtime_error("placeholder");
    }

    if (nfq_unbind_pf(m_nfq_handle, AF_INET) < 0) {
        m_log->error("nfq_unbind_pf() failed");

        throw std::runtime_error("placeholder");
    }

    if (nfq_bind_pf(m_nfq_handle, AF_INET) < 0) {
        m_log->error("nfq_bind_pf() failed");

        throw std::runtime_error("placeholder");
    }

    m_nfq_queue = nfq_create_queue(
        m_nfq_handle,
        0,
        &ebpfsnitch_daemon::nfq_cb,
        (void *)this
    );

    if (m_nfq_queue == NULL) {
        m_log->error("nfq_create_queue() failed");

        throw std::runtime_error("placeholder");
    }

    const uint32_t l_queue_flags = NFQA_CFG_F_UID_GID;
    const int l_flag_status = nfq_set_queue_flags(
        m_nfq_queue,
        l_queue_flags,
        l_queue_flags
    );

    if (l_flag_status != 0) {
        m_log->error("nfq_set_queue_flags() failed");

        throw std::runtime_error("placeholder");
    }

    if (nfq_set_mode(m_nfq_queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        m_log->error("nfq_set_mode() failed");

        throw std::runtime_error("placeholder");
    }

    m_nfq_fd = nfq_fd(m_nfq_handle);

    if (m_nfq_fd <= 0) {
        m_log->error("nfq_fd() failed");

        throw std::runtime_error("placeholder");
    }

    m_log->trace("adding iptables rules");
    std::system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");

    m_filter_thread = std::thread(&ebpfsnitch_daemon::filter_thread, this);

    m_log->trace("attaching kprobes");
    ebpf::StatusTuple l_attach_res = m_bpf.attach_kprobe(
        "tcp_v4_connect",
        "probe_connect_entry"
    );

    if (l_attach_res.code() != 0) {
        m_log->error("g_bpf.attach_kprobe() failed, {}", l_attach_res.msg());

        throw std::runtime_error("placeholder");
    }

    l_attach_res = m_bpf.attach_kprobe(
        "tcp_v4_connect",
        "probe_tcp_v4_connect_return",
        0,
        BPF_PROBE_RETURN
    );

    if (l_attach_res.code() != 0) {
        m_log->error("g_bpf.attach_kprobe() failed, {}", l_attach_res.msg());

        throw std::runtime_error("placeholder");
    }

    const ebpf::StatusTuple l_open_res = m_bpf.open_perf_buffer(
        "g_probe_ipv4_events",
        &ebpfsnitch_daemon::handle_probe_output,
        NULL,
        (void *)this
    );

    if (l_open_res.code() != 0) {
        m_log->error("g_bpf.open_perf_buffer() failed, {}", l_open_res.msg());

        throw std::runtime_error("placeholder");
    }

    m_perf_buffer = m_bpf.get_perf_buffer("g_probe_ipv4_events");

    if (m_perf_buffer == NULL) {
        m_log->error("g_bpf.get_perf_buffer() failed, {}");

        throw std::runtime_error("placeholder");
    }
    
    m_probe_thread = std::thread(&ebpfsnitch_daemon::probe_thread, this);
}

ebpfsnitch_daemon::~ebpfsnitch_daemon()
{
    m_log->trace("ebpfsnitch_daemon destructor");

    m_log->trace("removing iptables rules");
    std::system("iptables -D OUTPUT -j NFQUEUE --queue-num 0");

    m_log->trace("joining threads");
    m_shutdown.store(true);
    m_filter_thread.join();
    m_probe_thread.join();

    nfq_destroy_queue(m_nfq_queue);
    nfq_close(m_nfq_handle);

    m_log->trace("detaching ebpf kprobes");
    /*
    const ebpf::StatusTuple l_detach_res = m_bpf.detach_kprobe(clone_fnname);

    if (l_detach_res.code() != 0) {
        m_log->error("m_bpf.detach_kprobe() failed {}", l_detach_res.msg());
    }
    */
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
        m_perf_buffer->poll(100);
    }

    m_log->trace("ebpfsnitch_daemon::probe_thread() exit");
}

void
ebpfsnitch_daemon::handle_probe_output(
    void *const p_cb_cookie,
    void *const p_data,
    const int   p_data_size
){
    assert(p_cb_cookie);
    assert(p_data);

    class ebpfsnitch_daemon *const l_self =
        (class ebpfsnitch_daemon *const)p_cb_cookie;

    struct probe_ipv4_event_t *const l_info =
        static_cast<probe_ipv4_event_t *>(p_data);

    const std::string l_destination_address =
        ipv4_to_string(l_info->m_destination_address);

    const std::string l_source_address =
        ipv4_to_string(l_info->m_destination_address);

    const std::string l_path = 
        "/proc/" +
        std::to_string(l_info->m_process_id) +
        "/exe";

    char l_readlink_buffer[1024 * 32 + 1];
    l_readlink_buffer[sizeof(l_readlink_buffer) - 1] = '\0';

    const ssize_t l_readlink_status = readlink(
        l_path.c_str(),
        l_readlink_buffer,
        sizeof(l_readlink_buffer) - 1
    );

    if (l_readlink_status == -1) {
        l_self->m_log->error("failed to read link {}", l_path);
    }
    
    const std::string l_command_line = std::string(l_readlink_buffer);

    l_self->m_log->info(
        "got event uid {} pid {} sourcePort {} sourceAddress {} "
        "destinationPort {} destinationAddress {}",
        l_info->m_user_id,
        l_info->m_process_id,
        l_info->m_source_port,
        l_source_address,
        l_info->m_destination_port,
        l_destination_address
    );

    const std::string l_key =
        std::to_string(l_info->m_source_port) +
        std::to_string(l_info->m_destination_port);

    struct connection_info_t l_info2;
    l_info2.m_user_id    = l_info->m_user_id;
    l_info2.m_process_id = l_info->m_process_id;
    l_info2.m_executable = l_command_line;

    std::lock_guard<std::mutex> l_guard(l_self->m_lock);
    l_self->m_mapping[l_key] = l_info2;
}

int
ebpfsnitch_daemon::nfq_cb(
    struct nfq_q_handle *const p_qh,
    struct nfgenmsg *const     p_nfmsg,
    struct nfq_data *const     p_nfa,
    void *const                p_data
){
    assert(p_data);

    class ebpfsnitch_daemon *const l_self =
        (class ebpfsnitch_daemon *const)p_data;

    struct nfqnl_msg_packet_hdr *l_header = nfq_get_msg_packet_hdr(p_nfa);	
    const u_int32_t l_id = ntohl(l_header->packet_id);

    unsigned char *l_data = NULL;

    u_int32_t l_packet_user_id = 0;
    if (nfq_get_uid(p_nfa, &l_packet_user_id) == 0) {
        // std::cout << "nfq_get_uid() failed" << std::endl;
    }

    u_int32_t l_packet_group_id = 0;
    if (nfq_get_gid(p_nfa, &l_packet_group_id) == 0) {
        // std::cout << "nfq_get_gid() failed" << std::endl;
    }

    const int l_ret = nfq_get_payload(p_nfa, &l_data);
    if (l_ret >= 0) {
        assert(l_ret >= 20);

        uint8_t l_protocol = *((uint8_t*) (l_data + 9));
        
        if (l_protocol != 6) {
            l_self->m_log->info(
                "allowing unknown protocol "
                "userId {} groupId {} protocol {}",
                l_packet_user_id,
                l_packet_group_id,
                l_protocol
            );
    
            return nfq_set_verdict(p_qh, l_id, NF_ACCEPT, 0, NULL);
        }

        if (l_ret >= 24) {
            const uint16_t l_src_port = *((uint16_t*) (l_data + 20));
            const uint16_t l_dst_port = *((uint16_t*) (l_data + 22));

            const std::string l_key =
                std::to_string(ntohs(l_src_port)) +
                std::to_string(ntohs(l_dst_port));

            std::lock_guard<std::mutex> l_guard(l_self->m_lock);

            if (l_self->m_mapping.find(l_key) != l_self->m_mapping.end()) {
                const struct connection_info_t l_info =
                    l_self->m_mapping[l_key];

                if (l_info.m_executable.find("curl") != std::string::npos) {
                    l_self->m_log->info("blocking curl");
                    
                    return nfq_set_verdict(p_qh, l_id, NF_DROP, 0, NULL);
                } else {
                    l_self->m_log->info(
                        "letting through: {} sourcePort {} destinationPort {} "
                        "userId {} processId {}",
                        l_info.m_executable,
                        ntohs(l_src_port),
                        ntohs(l_dst_port),
                        l_info.m_user_id,
                        l_info.m_process_id
                    );
                }
            } else {
                l_self->m_log->info(
                    "unknown source packet sourcePort {} destinationPort {} "
                    "userId {} groupId {}",
                    ntohs(l_src_port),
                    ntohs(l_dst_port),
                    l_packet_user_id,
                    l_packet_group_id
                );
            }
        } else {
            l_self->m_log->error("packet smaller than minimum tcp size");
        }
    } else {
        l_self->m_log->info("ret is", l_ret);
    }

    return nfq_set_verdict(p_qh, l_id, NF_ACCEPT, 0, NULL);
}

std::shared_ptr<spdlog::logger> g_log;

std::string
file_to_string(const std::string &p_path) {
    std::ifstream l_stream(p_path);

    if (l_stream.is_open() == false) {
        throw std::runtime_error("std::ifstream() failed");
    }

    return std::string(
        (std::istreambuf_iterator<char>(l_stream)),
        std::istreambuf_iterator<char>()
    );
}

std::string
ipv4_to_string(const uint32_t p_address)
{
    char l_buffer[INET_ADDRSTRLEN];

    const char *const l_status = inet_ntop(
        AF_INET,
        &p_address,
        l_buffer,
        INET_ADDRSTRLEN
    );

    if (l_status == NULL) {
        throw std::runtime_error("inet_ntop() failed");
    }

    return std::string(l_buffer);
}

static void
trace_ebpf()
{
    std::ifstream l_pipe("/sys/kernel/debug/tracing/trace_pipe");
    std::string l_line;

    while (true) {
        if (std::getline(l_pipe, l_line)) {
            g_log->trace("eBPF log: {}", l_line);
        } else {
            sleep(1);
        }
    }
}

std::shared_ptr<ebpfsnitch_daemon> g_daemon;
std::condition_variable g_shutdown;
std::mutex g_shutdown_mutex;

static void
signal_handler(const int p_sig)
{
    g_log->info("signal_handler");

    g_daemon.reset();

    g_shutdown.notify_all();
}

int
main()
{
    g_log = spdlog::stdout_color_mt("console");
    g_log->set_level(spdlog::level::trace);

    g_log->info("LIBBCC_VERSION: {}", LIBBCC_VERSION);

    signal(SIGINT, signal_handler); 

    g_daemon = std::make_shared<ebpfsnitch_daemon>(g_log);

    std::unique_lock<std::mutex> l_lock(g_shutdown_mutex);
    g_shutdown.wait(l_lock);

    g_log->info("post g_shutdown condition");

    return 0;
}