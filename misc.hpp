#pragma once

#include <optional>

// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/netfilter_ipv4.h#L16
enum class nf_hook_t : uint8_t {
    // After promisc drops, checksum checks.
    IP_PRE_ROUTING  = 0,
    // If the packet is destined for this box.
    IP_LOCAL_IN     = 1,
    // If the packet is destined for another interface.
    IP_FORWARD      = 2,
    // Packets coming from a local process
    IP_LOCAL_OUT    = 3,
    // Packets about to hit the wire.
    IP_POST_ROUTING = 4
};

std::string
nf_hook_to_string(const nf_hook_t p_hook);

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

struct connection_info_t {
    uint32_t    m_user_id;
    uint32_t    m_process_id;
    std::string m_executable;
    std::string m_container;
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

struct process_info_t {
    std::string                m_executable;
    std::optional<std::string> m_container_id;
};

std::string
ipv4_to_string(const uint32_t p_address);

std::string
file_to_string(const std::string &p_path);

uint64_t
nanoseconds();

std::string
ip_protocol_to_string(const ip_protocol_t p_protocol);