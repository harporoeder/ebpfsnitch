#pragma once

#include "nfq_wrapper.hpp"

struct nfq_event_t {
    bool          m_v6;
    uint32_t      m_user_id;
    uint32_t      m_group_id;
    uint32_t      m_source_address;
    __uint128_t   m_source_address_v6;
    uint16_t      m_source_port;
    uint32_t      m_destination_address;
    __uint128_t   m_destination_address_v6;
    uint16_t      m_destination_port;
    uint32_t      m_nfq_id;
    uint64_t      m_timestamp;
    ip_protocol_t m_protocol;
    nfq_wrapper * m_queue;
};
