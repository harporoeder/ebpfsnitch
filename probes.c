#define bpf_target_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct probe_ipv4_event_t {
    void *   m_handle;
    bool     m_tcp;
    bool     m_remove;
    uint32_t m_user_id;
    uint32_t m_process_id;
    uint32_t m_source_address;
    uint16_t m_source_port;
    uint32_t m_destination_address;
    uint16_t m_destination_port;
    uint64_t m_timestamp;
} __attribute__((packed));

struct bpf_map_def SEC("maps") g_probe_ipv4_events = {
    .type        = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 4096 * 64
};

struct bpf_map_def SEC("maps") g_ipv4_tcp_connect_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(uint64_t),
    .value_size  = sizeof(struct sock *),
    .max_entries = 1000
};

struct bpf_map_def SEC("maps") g_send_map1 = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(uint64_t),
    .value_size  = sizeof(struct socket *),
    .max_entries = 1000
};

struct bpf_map_def SEC("maps") g_send_map2 = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(uint64_t),
    .value_size  = sizeof(struct msghdr *),
    .max_entries = 1000
};

#define AF_INET 2

// BPF_HASH(g_ipv4_tcp_connect_map, uint64_t, struct sock *);

SEC("kprobe/tcp_v4_connect") int
msend2(const struct pt_regs *const p_context)
{
    struct sock *const l_sock = (void *)PT_REGS_PARM1(p_context);

    uint64_t l_id = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&g_ipv4_tcp_connect_map, &l_id, &l_sock, 0);

    return 0;
}

SEC("kretprobe/tcp_v4_connect") int
msend2ret(const struct pt_regs *const p_context)
{
    uint64_t l_id  = bpf_get_current_pid_tgid();
    uint32_t l_pid = l_id >> 32;

    struct sock **l_sock_ref = bpf_map_lookup_elem(
        &g_ipv4_tcp_connect_map,
        &l_id
    );

    if (!l_sock_ref) {
        // bpf_trace_printk("tcp_v4_connect_return no entry");

        return 0;
    }

    struct sock *l_sock = *l_sock_ref;

    uint16_t                  l_source_port;
    uint16_t                  l_destination_port;
    uint32_t                  l_source_address;
    uint32_t                  l_destination_address;

    bpf_probe_read(
        &l_source_port,
        sizeof(l_source_port),
        &l_sock->__sk_common.skc_num
    );

    bpf_probe_read(
        &l_destination_port,
        sizeof(l_destination_port),
        &l_sock->__sk_common.skc_dport
    );

    bpf_probe_read(
        &l_source_address,
        sizeof(l_source_address),
        &l_sock->__sk_common.skc_rcv_saddr
    );

    bpf_probe_read(
        &l_destination_address,
        sizeof(l_destination_address),
        &l_sock->__sk_common.skc_daddr
    );

    struct probe_ipv4_event_t *const l_event = bpf_ringbuf_reserve(
        &g_probe_ipv4_events,
        sizeof(struct probe_ipv4_event_t),
        0
    );

    if (!l_event) {
        return 0;
    }

    l_event->m_timestamp           = bpf_ktime_get_ns();
    l_event->m_user_id             = bpf_get_current_uid_gid();
    l_event->m_process_id          = l_pid;
    l_event->m_handle              = l_sock;
    l_event->m_remove              = false;
    l_event->m_tcp                 = true;
    l_event->m_source_address      = l_source_address;
    l_event->m_source_port         = l_source_port;
    l_event->m_destination_port    = l_destination_port;
    l_event->m_destination_address = l_destination_address;

    bpf_ringbuf_submit(l_event, BPF_RB_FORCE_WAKEUP);

    return 0;
}

// clang -O2 -target bpf -c bpf.c -o bpf.o
// struct socket *sock, struct msghdr *msg, int size

SEC("kprobe/security_socket_sendmsg") int
msend(const struct pt_regs *const p_context)
{
    struct socket *const l_socket = (void *)PT_REGS_PARM1(p_context);
    struct msghdr *const l_msg    = (void *)PT_REGS_PARM2(p_context);

    uint64_t l_id = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&g_send_map1, &l_id, &l_socket, 0);
    bpf_map_update_elem(&g_send_map2, &l_id, &l_msg, 0);

    return 0;
}

SEC("kretprobe/security_socket_sendmsg") int
msendret(const struct pt_regs *const p_context_ignore)
{
    uint64_t l_id  = bpf_get_current_pid_tgid();

    struct socket **l_sock_ref = bpf_map_lookup_elem(
        &g_send_map1,
        &l_id
    );

    struct msghdr **l_msg_ref = bpf_map_lookup_elem(
        &g_send_map2,
        &l_id
    );

    if (!l_sock_ref) {
        // bpf_trace_printk("tcp_v4_connect_return no entry");

        return 0;
    }

    if (!l_msg_ref) {
        return 0;
    }

    struct socket *l_socket = *l_sock_ref;
    struct msghdr *l_msg  = *l_msg_ref;

    const struct sock *       l_sock;
    const struct sockaddr_in *l_usin;
    short int                 l_type;
    sa_family_t               l_family;
    uint16_t                  l_source_port;
    uint16_t                  l_destination_port;
    uint32_t                  l_source_address;
    uint32_t                  l_destination_address;

    bpf_probe_read(
        &l_sock,
        sizeof(l_sock),
        &l_socket->sk
    );

    bpf_probe_read(
        &l_family,
        sizeof(l_family),
        &l_sock->__sk_common.skc_family
    );

    if (l_family != AF_INET) {
        return 0;
    }

    bpf_probe_read(
        &l_type,
        sizeof(l_type),
        &l_socket->type
    );

    if (l_type != SOCK_DGRAM) {
        return 0;
    }

    bpf_probe_read(
        &l_source_port,
        sizeof(l_source_port),
        &l_sock->__sk_common.skc_num
    );

    bpf_probe_read(
        &l_source_address,
        sizeof(l_source_address),
        &l_sock->__sk_common.skc_rcv_saddr
    );

    bpf_probe_read(
        &l_usin,
        sizeof(l_usin),
        &l_msg->msg_name
    );

    bpf_probe_read(
        &l_destination_port,
        sizeof(l_destination_port),
        &l_usin->sin_port
    );

    if (l_destination_port == 0) {
        bpf_probe_read(
            &l_destination_port,
            sizeof(l_destination_port),
            &l_sock->__sk_common.skc_dport
        );
    }

    bpf_probe_read(
        &l_destination_address,
        sizeof(l_destination_address),
        &l_usin->sin_addr
    );

    if (l_destination_address == 0) {
        bpf_probe_read(
            &l_destination_address,
            sizeof(l_destination_address),
            &l_sock->__sk_common.skc_daddr
        );
    }
    
    struct probe_ipv4_event_t *const l_event = bpf_ringbuf_reserve(
        &g_probe_ipv4_events,
        sizeof(struct probe_ipv4_event_t),
        0
    );

    if (!l_event) {
        return 0;
    }

    l_event->m_timestamp           = bpf_ktime_get_ns();
    l_event->m_user_id             = bpf_get_current_uid_gid();
    l_event->m_process_id          = bpf_get_current_pid_tgid() >> 32;
    l_event->m_handle              = l_socket;
    l_event->m_remove              = false;
    l_event->m_tcp                 = false;
    l_event->m_source_address      = l_source_address;
    l_event->m_source_port         = l_source_port;
    l_event->m_destination_port    = l_destination_port;
    l_event->m_destination_address = l_destination_address;

    bpf_ringbuf_submit(l_event, BPF_RB_FORCE_WAKEUP);

    return 0;
}
