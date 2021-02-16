#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <net/inet_sock.h>

BPF_HASH(g_sock_map, u32, struct sock *);

struct probe_ipv4_event_t {
    u32 m_user_id;
    u32 m_process_id;
    u32 m_source_address;
    u16 m_source_port;
    u32 m_destination_address;
    u16 m_destination_port;
} __attribute__((packed));

BPF_PERF_OUTPUT(g_probe_ipv4_events);

int
probe_connect_entry(struct pt_regs *const p_ctx, struct sock *p_sk)
{
    u32 l_tid = bpf_get_current_pid_tgid();

    g_sock_map.update(&l_tid, &p_sk);

    return 0;
}

int
probe_tcp_v4_connect_return(struct pt_regs *const p_ctx)
{
    u64 l_pid_tgid = bpf_get_current_pid_tgid();
    u32 l_pid      = l_pid_tgid >> 32;
    u32 l_tid      = l_pid_tgid;

    struct sock **l_sock_ref = g_sock_map.lookup(&l_tid);

    if (l_sock_ref == NULL) {
        return 0;
    }

    struct sock *l_sock = *l_sock_ref;

    struct probe_ipv4_event_t l_data;
    l_data.m_user_id    = bpf_get_current_uid_gid();
    l_data.m_process_id = l_pid;

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

    g_probe_ipv4_events.perf_submit(p_ctx, &l_data, sizeof(l_data));

    return 0;
}