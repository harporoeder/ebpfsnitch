#pragma once

#include <string>
#include <optional>

enum class dns_class : uint16_t {
    INTERNET = 1,
    CSNET    = 2,
    CHAOS    = 3,
    HESOID   = 4 
};

// https://en.wikipedia.org/wiki/List_of_DNS_record_types
enum class dns_resource_record_type : uint16_t {
    A     = 1,
    NS    = 2,
    CNAME = 5,
    SOA   = 6,
    PTR   = 12,
    HINFO = 13,
    MX    = 15,
    TXT   = 16,
    RP    = 17,
    AFSDB = 18,
    SIG   = 24,
    KEY   = 25,
    AAAA  = 28,
    LOC   = 29,
    SRV   = 33
};

struct dns_header_t {
    uint16_t m_question_count;
    uint16_t m_answer_count;
    uint16_t m_authority_count;
    uint16_t m_additional_count;
};

struct dns_question_t {
    const char *             m_name;
    dns_resource_record_type m_type;
    dns_class                m_class;
};

struct dns_resource_record_t {
    const char *             m_name;
    dns_resource_record_type m_type;
    dns_class                m_class;
    uint32_t                 m_ttl;
    uint16_t                 m_data_length;
    const char *             m_data;
};

bool
dns_parse_header(
    const char *const          p_packet,
    const size_t               p_packet_size,
    struct dns_header_t *const p_result
) __attribute__((nonnull (1, 3)));

const char *
dns_parse_question(
    const char *const            p_packet,
    const size_t                 p_packet_size,
    const char *                 p_iter,
    struct dns_question_t *const p_result
) __attribute__((nonnull (1, 3, 4)));

const char *
dns_parse_record(
    const char *const                   p_packet,
    const size_t                        p_packet_size,
    const char *                        p_iter,
    struct dns_resource_record_t *const p_result
) __attribute__((nonnull (1, 3, 4)));

std::optional<std::string>
dns_decode_qname(
    const char *const p_packet,
    const size_t      p_packet_size,
    const char *      p_iter,
    const bool        p_recurse=true
) __attribute__((nonnull (1, 3)));

const char *
dns_get_body(const char *const p_buffer __attribute__((nonnull)));

uint16_t
read_network_u16(const char *const p_buffer __attribute__((nonnull)));
