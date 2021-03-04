#pragma once

#include <cstdint>
#include <vector>
#include <functional>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter.h>
#include <libmnl/libmnl.h>

class nfq_wrapper {
public:
    nfq_wrapper(
        const unsigned int                          p_queue_index,
        std::function<int(const struct nlmsghdr *)> p_cb
    );

    ~nfq_wrapper();

    int get_fd();

    void step();

    void send_verdict(const uint32_t p_id, const bool p_allow);

private:
    std::vector<char> m_buffer;

    struct mnl_socket *m_socket;

    unsigned int m_port_id;

    static int queue_cb_proxy(
        const struct nlmsghdr *const p_header,
        void *const                  p_context
    );

    std::function<int(const struct nlmsghdr *)> m_cb;
};
