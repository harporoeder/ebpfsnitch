#include <stdexcept>

#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "nfq_wrapper.hpp"

nfq_wrapper::nfq_wrapper(
    const unsigned int                          p_queue_index,
    std::function<int(const struct nlmsghdr *)> p_cb
):
    m_buffer(0xffff + (MNL_SOCKET_BUFFER_SIZE/2)),
    m_cb(p_cb)
{
    m_socket = mnl_socket_open(NETLINK_NETFILTER);

    if (m_socket == NULL) {
        throw std::runtime_error("mnl_socket_open() failed");
    }

    if (mnl_socket_bind(m_socket, 0, MNL_SOCKET_AUTOPID) < 0) {
        throw std::runtime_error("mnl_socket_bind() failed");
    }

    struct nlmsghdr *l_header;

    l_header = nfq_nlmsg_put(m_buffer.data(), NFQNL_MSG_CONFIG, p_queue_index);

    if (l_header == NULL) {
        throw std::runtime_error("nfq_nlmsg_put() failed");
    }

    nfq_nlmsg_cfg_put_cmd(l_header, AF_INET, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(m_socket, l_header, l_header->nlmsg_len) < 0) {
        throw std::runtime_error("mnl_socket_sendto() failed");
    }

    l_header = nfq_nlmsg_put(m_buffer.data(), NFQNL_MSG_CONFIG, p_queue_index);

    if (l_header == NULL) {
        throw std::runtime_error("nfq_nlmsg_put() failed");
    }

    nfq_nlmsg_cfg_put_params(l_header, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32(l_header, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(l_header, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if (mnl_socket_sendto(m_socket, l_header, l_header->nlmsg_len) < 0) {
        throw std::runtime_error("mnl_socket_sendto() failed");
    }

    m_port_id = mnl_socket_get_portid(m_socket);
}

nfq_wrapper::~nfq_wrapper()
{
    mnl_socket_close(m_socket);
}

int
nfq_wrapper::get_fd()
{
    return mnl_socket_get_fd(m_socket);
}

int nfq_wrapper::queue_cb_proxy(
    const struct nlmsghdr *const p_header,
    void *const                  p_context
) {
    class nfq_wrapper *const l_self = (class nfq_wrapper *const)p_context;

    assert(l_self != NULL);

    return 0;
}

void
nfq_wrapper::step()
{
    const int l_status = mnl_socket_recvfrom(
        m_socket,
        m_buffer.data(),
        m_buffer.size()
    );

    if (l_status < 0) {
        if (errno == ENOBUFS) {
            return;
        } else {
            throw std::runtime_error(
                "mnl_socket_recvfrom()" + std::string(strerror(errno))
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
        throw std::runtime_error("mnl_cb_run() failed");
    }
}

void
nfq_wrapper::send_verdict(const uint32_t p_id, const bool p_allow)
{
    char l_buffer[MNL_SOCKET_BUFFER_SIZE];

    struct nlmsghdr *l_header = nfq_nlmsg_put(l_buffer, NFQNL_MSG_VERDICT, 0);

    if (l_header == NULL) {
        throw std::runtime_error("nfq_nlmsg_put() failed");
    }

    if (p_allow) {
        nfq_nlmsg_verdict_put(l_header, p_id, NF_ACCEPT);
    } else {
        nfq_nlmsg_verdict_put(l_header, p_id, NF_DROP);
    }

    if (mnl_socket_sendto(m_socket, l_header, l_header->nlmsg_len) < 0) {
        throw std::runtime_error("mnl_socket_sendto() failed");
    }
}