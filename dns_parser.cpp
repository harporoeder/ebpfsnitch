#include <cassert>
#include <cstddef>
#include <iostream>

#include <arpa/inet.h>

#include "dns_parser.hpp"

uint16_t
read_network_u16(const char *const l_buffer)
{
    assert(l_buffer);

    return ntohs(*((uint16_t *)l_buffer));
}

uint16_t
dns_get_question_count(const char *const l_buffer)
{
    assert(l_buffer);

    return read_network_u16(l_buffer + 4);
}

uint16_t
dns_get_answer_count(const char *const l_buffer)
{
    assert(l_buffer);

    return read_network_u16(l_buffer + 6);
}

uint16_t
dns_get_authority_count(const char *const l_buffer)
{
    assert(l_buffer);

    return read_network_u16(l_buffer + 8);
}

uint16_t
dns_get_additional_count(const char *const l_buffer)
{
    assert(l_buffer);

    return read_network_u16(l_buffer + 10);
}

const char *
dns_get_body(const char *const l_buffer)
{
    assert(l_buffer);

    return l_buffer + 12;
}

std::string
dns_decode_qname(const char *const p_qname)
{
    std::string l_buffer;

    for (uint8_t l_i = 0; p_qname[l_i] != '\0';) {
        const uint8_t l_count = p_qname[l_i];

        if (l_count > 63) {
            return l_buffer;
        }

        l_i++;
        l_buffer += std::string(p_qname + l_i, l_count) + ".";
        l_i += l_count;
    }

    return l_buffer;
}


static const char *
dns_validate_qname(const char *const p_buffer, const char *const p_end)
{
    assert(p_buffer);
    assert(p_end);

    if (p_buffer >= p_end) {
        return NULL;
    }

    const char *l_iter = p_buffer;

    while (true) {
        const uint8_t l_byte = *l_iter;

        l_iter++;

        if (l_byte == 0) {
            return l_iter;
        } else if (l_byte > 63) {
            return l_iter + 1;
        }

        l_iter += l_byte;
    }

    return l_iter;
}

const char *
dns_get_question(
    const char *                 p_iter,
    struct dns_question_t *const p_question,
    const char *const            p_end
){
    assert(p_iter);
    assert(p_question);
    assert(p_end);

    p_question->m_name = p_iter;

    p_iter = dns_validate_qname(p_iter, p_end);

    if (p_iter == NULL || p_iter + 4 > p_end) {
        return NULL;
    }

    p_question->m_type = read_network_u16(p_iter);
    p_iter += 2;

    p_question->m_class = read_network_u16(p_iter);
    p_iter += 2;

    return p_iter;
}

const char *
dns_get_record(
    const char *                        p_iter,
    struct dns_resource_record_t *const p_record,
    const char *const                   p_end
){
    assert(p_iter);
    assert(p_record);
    assert(p_end);

    p_record->m_name = p_iter;

    p_iter = dns_validate_qname(p_iter, p_end);

    if (p_iter == NULL || (p_iter + 10) > p_end) {
        return NULL;
    }

    p_record->m_type = read_network_u16(p_iter);
    p_iter += 2;

    p_record->m_class = read_network_u16(p_iter);
    p_iter += 2;

    // skip ttl
    p_iter += 4;

    p_record->m_data_length = read_network_u16(p_iter);
    p_iter += 2;

    p_record->m_data = p_iter;

    p_iter += p_record->m_data_length;

    return p_iter;
}