#pragma once

#include <string>

const size_t DNS_HEADER_SIZE = 12;

struct dns_question_t {
    const char *m_name;
    uint16_t    m_type;
    uint16_t    m_class;
};

struct dns_resource_record_t {
    const char *m_name;
    uint16_t    m_type;
    uint16_t    m_class;
    uint32_t    m_ttl;
    uint16_t    m_data_length;
    const char *m_data;
};

uint16_t
read_network_u16(const char *const p_buffer);

uint16_t
dns_get_question_count(const char *const p_buffer);

uint16_t
dns_get_answer_count(const char *const p_buffer);

uint16_t
dns_get_authority_count(const char *const p_buffer);

uint16_t
dns_get_additional_count(const char *const p_buffer);

const char *
dns_get_body(const char *const p_buffer);

const char *
dns_get_question(
    const char *                 p_iter,
    struct dns_question_t *const p_question,
    const char *const            p_end
);

const char *
dns_get_record(
    const char *                        p_iter,
    struct dns_resource_record_t *const p_record,
    const char *const                   p_end
);

std::string
dns_decode_qname(const char *const p_qname);