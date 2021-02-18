#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <net/inet_sock.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(g_ipv4_tcp_connect_map, u64, struct sock *);

struct probe_ipv4_event_t {
    void *m_handle;
    bool  m_remove;
    u32   m_user_id;
    u32   m_process_id;
    u32   m_source_address;
    u16   m_source_port;
    u32   m_destination_address;
    u16   m_destination_port;
    u64   m_timestamp;
} __attribute__((packed));

BPF_PERF_OUTPUT(g_probe_ipv4_events);

int
probe_tcp_v4_connect_entry(
    struct pt_regs *const p_context,
    struct sock *         p_sock
) {
    u64 l_id = bpf_get_current_pid_tgid();

    g_ipv4_tcp_connect_map.update(&l_id, &p_sock);

    return 0;
}

int
probe_tcp_v4_connect_return(struct pt_regs *const p_context)
{
    u64 l_id  = bpf_get_current_pid_tgid();
    u32 l_pid = l_id >> 32;
    u32 l_tid = l_id;

    struct sock **l_sock_ref = g_ipv4_tcp_connect_map.lookup(&l_id);

    if (l_sock_ref == NULL) {
        bpf_trace_printk("tcp_v4_connect_return no entry");

        return 0;
    }

    struct sock *l_sock = *l_sock_ref;

    g_ipv4_tcp_connect_map.delete(&l_id);

    if (PT_REGS_RC(p_context) != 0) {
        return 0;
    }

    struct probe_ipv4_event_t l_data;
    memset(&l_data, 0, sizeof(l_data));

    l_data.m_user_id    = bpf_get_current_uid_gid();
    l_data.m_process_id = l_pid;
    l_data.m_handle     = l_sock;
    l_data.m_remove     = false;

    bpf_probe_read(
        &l_data.m_source_port,
        sizeof(l_data.m_source_port),
        &l_sock->__sk_common.skc_num
    );

    bpf_probe_read(
        &l_data.m_destination_port,
        sizeof(l_data.m_destination_port),
        &l_sock->__sk_common.skc_dport
    );

    l_data.m_destination_port = ntohs(l_data.m_destination_port);

    bpf_probe_read(
        &l_data.m_source_address,
        sizeof(l_data.m_source_address),
        &l_sock->__sk_common.skc_rcv_saddr
    );

    bpf_probe_read(
        &l_data.m_destination_address,
        sizeof(l_data.m_destination_address),
        &l_sock->__sk_common.skc_daddr
    );

    l_data.m_timestamp = bpf_ktime_get_ns();

    g_probe_ipv4_events.perf_submit(p_context, &l_data, sizeof(l_data));

    return 0;
}

TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    u32 l_uid = bpf_get_current_uid_gid();
    u32 l_pid = bpf_get_current_pid_tgid() >> 32;
    
    struct sock *l_sk = (struct sock *)args->skaddr;

    if (args->protocol != IPPROTO_TCP) {
        // bpf_trace_printk("probe not tcp");

        return 0;
    }

    if (args->newstate == TCP_CLOSE) {
        struct probe_ipv4_event_t l_data;
        memset(&l_data, 0, sizeof(l_data));

        l_data.m_handle = l_sk;
        l_data.m_remove = true;;

        g_probe_ipv4_events.perf_submit(args, &l_data, sizeof(l_data));
    }

    return 0;
}