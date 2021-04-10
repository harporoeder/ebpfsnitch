#pragma once

#include <cstdint>
#include <vector>
#include <functional>
#include <memory>
#include <mutex>
#include <span>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter.h>
#include <libmnl/libmnl.h>

#include "misc.hpp"

// https://elixir.bootlin.com/linux/v4.4/source/include/uapi/linux/netfilter.h
enum class nfq_verdict_t : int {
    DROP   = 0,
    ACCEPT = 1,
    STOLEN = 2,
    QUEUE  = 3,
    REPEAT = 4,
    STOP   = 5
};

// https://www.nftables.org/projects/libmnl/doxygen/html/libmnl_8h_source.html
enum class nfq_cb_result_t : int {
    ERROR = -1,
    STOP  = 0,
    OK    = 1
};

class nfq_wrapper {
public:
    typedef std::function<nfq_cb_result_t (
        nfq_wrapper *,
        uint32_t,
        const std::span<const std::byte> &
    )> cb_t;

    nfq_wrapper(
        const unsigned int     p_queue_index,
        cb_t                   p_cb,
        const address_family_t p_family
    );

    ~nfq_wrapper();

    int get_fd();

    void step();

    void send_verdict(const uint32_t p_id, const nfq_verdict_t p_verdict);

private:
    std::vector<char> m_buffer;

    const std::unique_ptr<struct mnl_socket, int(*)(struct mnl_socket *)>
        m_socket;

    const unsigned int m_queue_index;

    unsigned int m_port_id;

    static int queue_cb_proxy(
        const struct nlmsghdr *const p_header,
        void *const                  p_context
    );

    const cb_t m_cb;

    std::mutex m_send_lock;
};
