#pragma once

#include <string>
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

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
enum class ip_protocol_t : uint8_t {
    HOPOPT    = 0,
    ICMP      = 1,
    IGMP      = 2,
    GGP       = 3,
    IPV4      = 4,
    ST        = 5,
    TCP       = 6,
    CBT       = 7,
    EGP       = 8,
    IGP       = 9,
    BBNRCCMON = 10,
    NVPII     = 11,
    PUP       = 12,
    ARGUS     = 13,
    EMCON     = 14,
    XNET      = 15,
    CHAOS     = 16,
    UDP       = 17
};

std::string
ip_protocol_to_string(const ip_protocol_t p_protocol);

ip_protocol_t
ip_protocol_from_string(const std::string &p_protocol);

// https://github.com/torvalds/linux/blob/master/include/linux/socket.h#L175
enum class address_family_t : uint16_t {
    INET  = 2,
    INET6 = 10
};

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
};

std::string
ipv4_to_string(const uint32_t p_address);

std::string
ipv6_to_string(const __uint128_t p_address);

std::string
file_to_string(const std::string &p_path);

void
atomically_write_file(const std::string &p_path, const std::string &p_data);

uint64_t
nanoseconds();
