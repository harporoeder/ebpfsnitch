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

#include <bcc/bcc_version.h>
#include <bcc/BPF.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

struct probe_ipv4_event_t {
    uint32_t m_user_id;
    uint32_t m_process_id;
    uint32_t m_source_address;
    uint16_t m_source_port;
    uint32_t m_destination_address;
    uint16_t m_destination_port;
} __attribute__((packed));

// /proc/2217/ns/cgroup

ebpf::BPF g_bpf;

static std::string
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

static std::string
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
signal_handler(const int p_sig)
{
    std::cout << "tearing down iptables" << std::endl;

    std::system("iptables -D OUTPUT -j NFQUEUE --queue-num 0");
    // std::system("iptables -D DOCKER-USER -j NFQUEUE --queue-num 0");

    std::cout << "detaching probe" << std::endl;

    /*
    const ebpf::StatusTuple l_detach_res = bpf.detach_kprobe(clone_fnname);

    if (l_detach_res.code() != 0) {
        std::cerr << l_detach_res.msg() << std::endl;
    }
    */

    exit(0);
}

struct connection_info_t {
    uint32_t    m_user_id;
    uint32_t    m_process_id;
    std::string m_executable;
};

std::mutex g_lock;
std::unordered_map<std::string, struct connection_info_t> g_mapping;

static int
nfq_cb(
    struct nfq_q_handle *const p_qh,
    struct nfgenmsg *const     p_nfmsg,
    struct nfq_data *const     p_nfa,
    void *const                p_data
){
    unsigned char *l_data = (unsigned char *)p_data;
    
    struct nfqnl_msg_packet_hdr *l_header = nfq_get_msg_packet_hdr(p_nfa);	
    const u_int32_t l_id = ntohl(l_header->packet_id);

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
        if (l_ret >= 24) {
            const uint16_t l_src_port = *((uint16_t*) (l_data + 20));
            const uint16_t l_dst_port = *((uint16_t*) (l_data + 22));

            const std::string l_key =
                std::to_string(ntohs(l_src_port)) +
                std::to_string(ntohs(l_dst_port));

            std::lock_guard<std::mutex> l_guard(g_lock);

            if (g_mapping.find(l_key) != g_mapping.end()) {
                const struct connection_info_t l_info = g_mapping[l_key];

                if (l_info.m_executable.find("curl") != std::string::npos) {
                    std::cout << "blocking curl" << std::endl;
                    
                    return nfq_set_verdict(p_qh, l_id, NF_DROP, 0, NULL);
                } else {
                    std::cout << "letting through:"
                        << " "                 << l_info.m_executable
                        << " sourcePort "      << ntohs(l_src_port)
                        << " destinationPort " << ntohs(l_dst_port)
                        << " userId "          << l_info.m_user_id
                        << " processId "       << l_info.m_process_id
                        << std::endl;
                }
            } else {
                std::cout << "unknown source packet"
                    << " sourcePort "      << ntohs(l_src_port)
                    << " destinationPort " << ntohs(l_dst_port)
                    << " userId "          << l_packet_user_id
                    << " groupId "         << l_packet_group_id
                    << std::endl;
            }
        } else {
            std::cout << "packet smaller than minimum tcp" << std::endl;
        }
    }

    return nfq_set_verdict(p_qh, l_id, NF_ACCEPT, 0, NULL);
}

static void
filter_thread(const int p_fd, struct nfq_handle *const p_handle)
{
    int l_rv;
    char l_buffer[1024 * 64] __attribute__ ((aligned));

    assert(p_handle);

    while ((l_rv = recv(p_fd, l_buffer, sizeof(l_buffer), 0))) {
        nfq_handle_packet(p_handle, l_buffer, l_rv);
    }
}

static void
handle_probe_output(
    void *const p_cb_cookie,
    void *const p_data,
    const int   p_data_size
){
    // assert(p_cb_cookie);
    assert(p_data);

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
        std::cout << "failed to read link" << std::endl;
    }
    
    const std::string l_command_line = std::string(l_readlink_buffer);

    std::cout << "got event"
        << " uid "                << l_info->m_user_id
        << " pid "                << l_info->m_process_id
        << " sourcePort "         << l_info->m_source_port
        << " sourceAddress "      << l_source_address
        << " destinationPort "    << l_info->m_destination_port
        << " destinationAddress " << l_destination_address
        << std::endl;

    const std::string l_key =
        std::to_string(l_info->m_source_port) +
        std::to_string(l_info->m_destination_port);

    struct connection_info_t l_info2;
    l_info2.m_user_id    = l_info->m_user_id;
    l_info2.m_process_id = l_info->m_process_id;
    l_info2.m_executable = l_command_line;

    std::lock_guard<std::mutex> l_guard(g_lock);
    g_mapping[l_key] = l_info2;
}

static void
trace_ebpf()
{
    std::ifstream l_pipe("/sys/kernel/debug/tracing/trace_pipe");
    std::string l_line;

    while (true) {
        if (std::getline(l_pipe, l_line)) {
            std::cout << l_line << std::endl;
        } else {
            sleep(1);
        }
    }
}

int
main()
{    
    std::cout << "LIBBCC_VERSION: " << LIBBCC_VERSION << std::endl;

    std::cout << "compiling" << std::endl;

    const ebpf::StatusTuple l_init_res = g_bpf.init(file_to_string("probes.c"));

    if (l_init_res.code() != 0) {
        std::cerr << l_init_res.msg() << std::endl;

        return 1;
    }

    signal(SIGINT, signal_handler); 
    
    struct nfq_handle *const l_handle = nfq_open();

    if (l_handle == NULL) {
        std::cout << "nfq_open() failed" << std::endl;

        return 1;
    }

    if (nfq_unbind_pf(l_handle, AF_INET) < 0) {
        std::cout << "nfq_unbind_pf() failed" << std::endl;

        return 1;
    }

    if (nfq_bind_pf(l_handle, AF_INET) < 0) {
        std::cout << "nfq_bind_pf() failed" << std::endl;

        return 1;
    }

    struct nfq_q_handle *const l_queue =
        nfq_create_queue(l_handle,  0, &nfq_cb, NULL);

    if (!l_queue) {
        std::cout << "nfq_create_queue() failed" << std::endl;

        return 1;
    }

    if (nfq_set_mode(l_queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cout << "nfq_set_mode() failed" << std::endl;

        return 1;
    }

    int l_fd = nfq_fd(l_handle);

    if (l_fd <= 0) {
        std::cout << "nfq_fd() failed" << std::endl;

        return 1;
    }

    std::cout << "setting up iptables" << std::endl;
    std::system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    // std::system("iptables -I DOCKER-USER -j NFQUEUE --queue-num 0");
    
    std::thread thread(filter_thread, l_fd, l_handle);

    // nfq_destroy_queue(qh);

    // nfq_close(h);

    std::cout << "attaching probe" << std::endl;

    ebpf::StatusTuple l_attach_res = g_bpf.attach_kprobe(
        "tcp_v4_connect",
        "probe_connect_entry"
    );

    if (l_attach_res.code() != 0) {
        std::cerr << l_attach_res.msg() << std::endl;

        return 1;
    }

    l_attach_res = g_bpf.attach_kprobe(
        "tcp_v4_connect",
        "probe_tcp_v4_connect_return",
        0,
        BPF_PROBE_RETURN
    );

    if (l_attach_res.code() != 0) {
        std::cerr << l_attach_res.msg() << std::endl;

        return 1;
    }

    const ebpf::StatusTuple l_open_res = g_bpf.open_perf_buffer(
        "g_probe_ipv4_events",
        &handle_probe_output
    );

    if (l_open_res.code() != 0) {
        std::cerr << l_open_res.msg() << std::endl;

        return 1;
    }

    ebpf::BPFPerfBuffer *const l_perf_buffer =
        g_bpf.get_perf_buffer("g_probe_ipv4_events");

    if (!l_perf_buffer) {
        std::cout << "get_perf_buffer() failed" << std::endl;

        return 1;
    }
 
    while (true) {
        l_perf_buffer->poll(100);
    }
 
    signal_handler(SIGINT);

    return 0;
}