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

enum class ip_protocol_t : uint8_t {
    ICMP = 1,
    TCP  = 6,
    UDP  = 17
};

std::string
ipv4_to_string(const uint32_t p_address);

std::string
file_to_string(const std::string &p_path);

uint64_t
nanoseconds();

std::string
ip_protocol_to_string(const ip_protocol_t p_protocol);