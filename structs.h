#pragma once

struct probe_ipv4_event_t {
    void    *m_handle;
    bool     m_remove;
    uint32_t m_user_id;
    uint32_t m_process_id;
    uint32_t m_source_address;
    uint16_t m_source_port;
    uint32_t m_destination_address;
    uint16_t m_destination_port;
    uint64_t m_timestamp;
} __attribute__((packed));

struct connection_info_t {
    uint32_t    m_user_id;
    uint32_t    m_process_id;
    std::string m_executable;
};

struct nfq_event_t {
    uint32_t m_user_id;
    uint32_t m_group_id;
    uint32_t m_source_address;
    uint16_t m_source_port;
    uint32_t m_destination_address;
    uint16_t m_destination_port;
    uint32_t m_nfq_id;
    uint8_t  m_protocol;
    uint64_t m_timestamp;
};