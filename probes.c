#define bpf_target_x86

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct probe_ipv4_event_t {
    bool        m_v6;
    void *      m_handle;
    bool        m_remove;
    uint32_t    m_user_id;
    uint32_t    m_process_id;
    uint32_t    m_source_address;
    __uint128_t m_source_address_v6;
    uint16_t    m_source_port;
    uint32_t    m_destination_address;
    __uint128_t m_destination_address_v6;
    uint16_t    m_destination_port;
    uint64_t    m_timestamp;
    uint8_t     m_protocol;
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

struct bpf_map_def SEC("maps") g_ipv6_tcp_connect_map = {
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

SEC("kprobe/tcp_v4_connect") int
kprobe_tcp_v4_connect(const struct pt_regs *const p_context)
{
    struct sock *const l_sock = (void *)PT_REGS_PARM1(p_context);

    const uint64_t l_id = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&g_ipv4_tcp_connect_map, &l_id, &l_sock, 0);

    return 0;
}

SEC("kretprobe/tcp_v4_connect") int
kretprobe_tcp_v4_connect(const struct pt_regs *const p_context)
{
    const uint64_t l_id  = bpf_get_current_pid_tgid();
    const uint32_t l_pid = l_id >> 32;

    struct sock **const l_sock_ref = bpf_map_lookup_elem(
        &g_ipv4_tcp_connect_map,
        &l_id
    );

    if (!l_sock_ref) {
        return 0;
    }

    struct sock *const l_sock = *l_sock_ref;

    if (bpf_map_delete_elem(&g_ipv4_tcp_connect_map, &l_id) != 0) {
        bpf_printk("bpf_map_delete_elem failed");

        return 0;
    }

    uint16_t l_source_port;
    uint16_t l_destination_port;
    uint32_t l_source_address;
    uint32_t l_destination_address;

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

    l_event->m_v6                  = false;
    l_event->m_timestamp           = bpf_ktime_get_ns();
    l_event->m_user_id             = bpf_get_current_uid_gid();
    l_event->m_process_id          = l_pid;
    l_event->m_handle              = l_sock;
    l_event->m_remove              = false;
    l_event->m_protocol            = 6;
    l_event->m_source_address      = l_source_address;
    l_event->m_source_port         = l_source_port;
    l_event->m_destination_port    = l_destination_port;
    l_event->m_destination_address = l_destination_address;

    bpf_ringbuf_submit(l_event, BPF_RB_FORCE_WAKEUP);

    return 0;
}

SEC("kprobe/security_socket_sendmsg") int
kprobe_security_socket_send_msg(const struct pt_regs *const p_context)
{
    struct socket *const l_socket = (void *)PT_REGS_PARM1(p_context);
    struct msghdr *const l_msg    = (void *)PT_REGS_PARM2(p_context);

    const uint64_t l_id = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&g_send_map1, &l_id, &l_socket, 0);
    bpf_map_update_elem(&g_send_map2, &l_id, &l_msg, 0);

    return 0;
}

SEC("kprobe/tcp_v6_connect") int
kprobe_tcp_v6_connect(const struct pt_regs *const p_context)
{
    struct sock *const l_sock = (void *)PT_REGS_PARM1(p_context);

    const uint64_t l_id = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&g_ipv6_tcp_connect_map, &l_id, &l_sock, 0);

    return 0;
}

SEC("kretprobe/tcp_v6_connect") int
kretprobe_tcp_v6_connect(const struct pt_regs *const p_context)
{
    const uint64_t l_id  = bpf_get_current_pid_tgid();
    const uint32_t l_pid = l_id >> 32;

    struct sock **l_sock_ref = bpf_map_lookup_elem(
        &g_ipv6_tcp_connect_map,
        &l_id
    );

    if (!l_sock_ref) {
        bpf_printk("tcp_v6_connect_return no entry");

        return 0;
    }

    if (bpf_map_delete_elem(&g_ipv6_tcp_connect_map, &l_id) != 0) {
        bpf_printk("bpf_map_delete_elem failed");

        return 0;
    }

    struct sock *const l_sock      = *l_sock_ref;
    struct inet_sock *const l_inet = (struct inet_sock *)l_sock;

    uint16_t    l_source_port;
    uint16_t    l_destination_port;
    __uint128_t l_source_address;
    __uint128_t l_destination_address;

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
        &l_sock->__sk_common.skc_v6_rcv_saddr
    );

    bpf_probe_read(
        &l_destination_address,
        sizeof(l_destination_address),
        &l_sock->__sk_common.skc_v6_daddr
    );

    struct probe_ipv4_event_t *const l_event = bpf_ringbuf_reserve(
        &g_probe_ipv4_events,
        sizeof(struct probe_ipv4_event_t),
        0
    );

    if (!l_event) {
        return 0;
    }

    l_event->m_v6                  = true;
    l_event->m_timestamp           = bpf_ktime_get_ns();
    l_event->m_user_id             = bpf_get_current_uid_gid();
    l_event->m_process_id          = l_pid;
    l_event->m_handle              = l_sock;
    l_event->m_remove              = false;
    l_event->m_protocol            = 6;
    l_event->m_source_address_v6      = l_source_address;
    l_event->m_source_port         = l_source_port;
    l_event->m_destination_port    = l_destination_port;
    l_event->m_destination_address_v6 = l_destination_address;

    bpf_ringbuf_submit(l_event, BPF_RB_FORCE_WAKEUP);

    return 0;
}

SEC("kretprobe/security_socket_sendmsg") int
kretprobe_security_socket_send_msg(const struct pt_regs *const p_context_ignore)
{
    const uint64_t l_id  = bpf_get_current_pid_tgid();

    struct socket **const l_sock_ref = bpf_map_lookup_elem(
        &g_send_map1,
        &l_id
    );

    struct msghdr **const l_msg_ref = bpf_map_lookup_elem(
        &g_send_map2,
        &l_id
    );

    if (!l_sock_ref) {
        bpf_printk("bpf_map_lookup_elem l_sock_ref failed");

        return 0;
    }

    if (!l_msg_ref) {
        bpf_printk("bpf_map_lookup_elem l_msg_ref failed");

        return 0;
    }

    struct socket *const l_socket = *l_sock_ref;
    struct msghdr *const l_msg    = *l_msg_ref;

    if (bpf_map_delete_elem(&g_send_map1, &l_id) != 0) {
        bpf_printk("bpf_map_delete_elem failed");

        return 0;
    }

    if (bpf_map_delete_elem(&g_send_map2, &l_id) != 0) {
        bpf_printk("bpf_map_delete_elem failed");

        return 0;
    }

    const struct sock *       l_sock = 0;
    const struct sockaddr_in *l_usin = 0;
    short int                 l_type = 0;
    sa_family_t               l_family = 0;
    uint16_t                  l_source_port = 0;
    uint16_t                  l_destination_port = 0;
    uint32_t                  l_source_address = 0;
    uint32_t                  l_destination_address = 0;
    uint8_t                   l_protocol = 0;

    if (
        bpf_probe_read(
            &l_sock,
            sizeof(l_sock),
            &l_socket->sk
        ) != 0
    ) {
        bpf_printk("bpf_probe_read failed line %d", __LINE__);

        return 0;
    }

    if (
        bpf_probe_read(
            &l_family,
            sizeof(l_family),
            &l_sock->__sk_common.skc_family
        ) != 0
    ) {
        bpf_printk("bpf_probe_read failed line %d", __LINE__);

        return 0;
    }

    if (l_family != AF_INET) {
        return 0;
    }

    if (
        bpf_probe_read(
            &l_type,
            sizeof(l_type),
            &l_socket->type
        ) != 0
    ) {
        bpf_printk("bpf_probe_read failed line %d", __LINE__);

        return 0;
    }

    if (
        bpf_probe_read(
            &l_type,
            sizeof(l_type),
            &l_socket->type
        ) != 0
    ) {
        bpf_printk("bpf_probe_read failed line %d", __LINE__);

        return 0;
    }

    if (
        bpf_probe_read(
            &l_protocol,
            sizeof(l_protocol),
            &l_sock->sk_protocol
        ) != 0
    ) {
        bpf_printk("bpf_probe_read failed line %d", __LINE__);

        return 0;
    }

    if (
        bpf_probe_read(
            &l_source_port,
            sizeof(l_source_port),
            &l_sock->__sk_common.skc_num
        ) != 0
    ) {
        bpf_printk("bpf_probe_read failed line %d", __LINE__);

        return 0;
    }

    if (
        bpf_probe_read(
            &l_source_address,
            sizeof(l_source_address),
            &l_sock->__sk_common.skc_rcv_saddr
        ) != 0
    ) {
        bpf_printk("bpf_probe_read failed line %d", __LINE__);

        return 0;
    }

    if (
        bpf_probe_read(
            &l_usin,
            sizeof(l_usin),
            &l_msg->msg_name
        ) != 0
    ) {
        bpf_printk("bpf_probe_read failed line %d", __LINE__);

        return 0;
    }
    
    if (
        bpf_probe_read(
            &l_destination_port,
            sizeof(l_destination_port),
            &l_sock->__sk_common.skc_dport
        ) != 0 || l_destination_port == 0
    ) {
        if (
            bpf_probe_read(
                &l_destination_port,
                sizeof(l_destination_port),
                &l_usin->sin_port
            ) != 0
        ) {
            bpf_printk("bpf_probe_read port failed %d", __LINE__);

            return 0;
        }
    }

    if (
        bpf_probe_read(
            &l_destination_address,
            sizeof(l_destination_address),
            &l_sock->__sk_common.skc_daddr
        ) != 0 || l_destination_address == 0
    ) {
        if (
            bpf_probe_read(
                &l_destination_address,
                sizeof(l_destination_address),
                &l_usin->sin_addr
            ) != 0
        ) {
            bpf_printk("bpf_probe_read address failed %d", __LINE__);

            return 0;
        }
    }
    
    struct probe_ipv4_event_t *const l_event = bpf_ringbuf_reserve(
        &g_probe_ipv4_events,
        sizeof(struct probe_ipv4_event_t),
        0
    );

    if (!l_event) {
        bpf_printk("bpf_ringbuf_reserve failed %d", __LINE__);

        return 0;
    }

    l_event->m_v6                  = false;
    l_event->m_timestamp           = bpf_ktime_get_ns();
    l_event->m_user_id             = bpf_get_current_uid_gid();
    l_event->m_process_id          = bpf_get_current_pid_tgid() >> 32;
    l_event->m_handle              = l_socket;
    l_event->m_remove              = false;
    l_event->m_source_address      = l_source_address;
    l_event->m_source_port         = l_source_port;
    l_event->m_destination_port    = l_destination_port;
    l_event->m_destination_address = l_destination_address;
    l_event->m_protocol            = l_protocol;

    bpf_ringbuf_submit(l_event, BPF_RB_FORCE_WAKEUP);

    return 0;
}
