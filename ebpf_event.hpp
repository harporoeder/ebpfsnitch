#pragma once

struct ebpf_event_t {
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
