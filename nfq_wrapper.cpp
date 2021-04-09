#include <stdexcept>
#include <iostream>

#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "nfq_wrapper.hpp"

nfq_wrapper::nfq_wrapper(
    const unsigned int                                         p_queue_index,
    std::function<int(nfq_wrapper *, const struct nlmsghdr *)> p_cb,
    const address_family_t                                     p_family
):
    m_buffer(0xffff + (MNL_SOCKET_BUFFER_SIZE/2)),
    m_cb(p_cb),
    m_socket(mnl_socket_open(NETLINK_NETFILTER), &mnl_socket_close),
    m_queue_index(p_queue_index)
{
    if (m_socket == NULL) {
        throw std::runtime_error("mnl_socket_open() failed");
    }

    if (mnl_socket_bind(m_socket.get(), 0, MNL_SOCKET_AUTOPID) < 0) {
        throw std::runtime_error("mnl_socket_bind() failed");
    }

    struct nlmsghdr *l_header;

    l_header = nfq_nlmsg_put(m_buffer.data(), NFQNL_MSG_CONFIG, p_queue_index);

    if (l_header == NULL) {
        throw std::runtime_error("nfq_nlmsg_put() failed");
    }

    nfq_nlmsg_cfg_put_cmd(
        l_header,
        static_cast<uint16_t>(p_family),
        NFQNL_CFG_CMD_BIND
    );

    if (mnl_socket_sendto(m_socket.get(), l_header, l_header->nlmsg_len) < 0) {
        throw std::runtime_error("mnl_socket_sendto() failed");
    }

    l_header = nfq_nlmsg_put(m_buffer.data(), NFQNL_MSG_CONFIG, p_queue_index);

    if (l_header == NULL) {
        throw std::runtime_error("nfq_nlmsg_put() failed");
    }

    nfq_nlmsg_cfg_put_params(l_header, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32(l_header, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(l_header, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if (mnl_socket_sendto(m_socket.get(), l_header, l_header->nlmsg_len) < 0) {
        throw std::runtime_error("mnl_socket_sendto() failed");
    }

    m_port_id = mnl_socket_get_portid(m_socket.get());
}

nfq_wrapper::~nfq_wrapper() {}

int
nfq_wrapper::get_fd()
{
    return mnl_socket_get_fd(m_socket.get());
}

int nfq_wrapper::queue_cb_proxy(
    const struct nlmsghdr *const p_header,
    void *const                  p_context
) {
    nfq_wrapper *const l_self = (nfq_wrapper *const)p_context;

    assert(l_self != NULL);

    l_self->m_cb(l_self, p_header);

    return 0;
}

void
nfq_wrapper::step()
{
    const int l_status = mnl_socket_recvfrom(
        m_socket.get(),
        m_buffer.data(),
        m_buffer.size()
    );

    if (l_status < 0) {
        if (errno == ENOBUFS) {
            return;
        } else {
            throw std::runtime_error(
                "mnl_socket_recvfrom() " + std::string(strerror(errno))
            );
        }
    }

    const int l_status2 = mnl_cb_run(
        m_buffer.data(),
        l_status, 
        0,
        m_port_id,
        &nfq_wrapper::queue_cb_proxy,
        this
    );

    if (l_status2 < 0) {
        throw std::runtime_error(
            "mnl_cb_run() " + std::string(strerror(errno))
        );
    }
}

void
nfq_wrapper::send_verdict(const uint32_t p_id, const nfq_verdict_t p_verdict)
{
    char l_buffer[MNL_SOCKET_BUFFER_SIZE];

    std::lock_guard<std::mutex> l_guard(m_send_lock);

    struct nlmsghdr *const l_header = nfq_nlmsg_put(
        l_buffer,
        NFQNL_MSG_VERDICT,
        m_queue_index
    );

    if (l_header == NULL) {
        throw std::runtime_error("nfq_nlmsg_put()");
    }

    nfq_nlmsg_verdict_put(l_header, p_id, static_cast<int>(p_verdict));

    if (mnl_socket_sendto(m_socket.get(), l_header, l_header->nlmsg_len) < 0) {
        throw std::runtime_error("mnl_socket_sendto() failed");
    }
}