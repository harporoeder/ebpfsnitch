#include <cassert>
#include <cstddef>
#include <iostream>

#include <arpa/inet.h>

#include "dns_parser.hpp"

bool
dns_parse_header(
    const char *const          p_packet,
    const size_t               p_packet_size,
    struct dns_header_t *const p_result
) {
    assert(p_packet);
    assert(p_result);

    if (p_packet_size < 12) {
        return false;
    }

    p_result->m_question_count   = read_network_u16(p_packet + 4);
    p_result->m_answer_count     = read_network_u16(p_packet + 6);
    p_result->m_authority_count  = read_network_u16(p_packet + 8);
    p_result->m_additional_count = read_network_u16(p_packet + 10);

    return true;
}

const char *
dns_get_body(const char *const l_buffer)
{
    assert(l_buffer);

    return l_buffer + 12;
}

static const char *
dns_skip_qname(
    const char *const p_packet,
    const size_t      p_packet_size,
    const char *      p_iter
){
    assert(p_packet);
    assert(p_iter);

    while (p_iter < (p_packet + p_packet_size)) {
        const uint8_t l_byte = *p_iter;

        if (l_byte == 0) {
            return p_iter + 1;
        } else if (l_byte > 63) {
            if ((p_iter + 2) <= (p_packet + p_packet_size)) {
                return p_iter + 2;
            } else {
                return NULL;
            }
        } 
    
        p_iter += l_byte + 1;
    }

    return NULL;
}

const char *
dns_parse_question(
    const char *const            p_packet,
    const size_t                 p_packet_size,
    const char *                 p_iter,
    struct dns_question_t *const p_result
){
    assert(p_packet);
    assert(p_iter);
    assert(p_result);

    p_result->m_name = p_iter;

    p_iter = dns_skip_qname(p_packet, p_packet_size, p_iter);

    if ((p_iter == NULL) || ((p_iter + 4) > (p_packet + p_packet_size))) {
        return NULL;
    }

    p_result->m_type  = read_network_u16(p_iter);
    p_result->m_class = read_network_u16(p_iter + 2);

    return p_iter + 4;
}

const char *
dns_parse_record(
    const char *const                   p_packet,
    const size_t                        p_packet_size,
    const char *                        p_iter,
    struct dns_resource_record_t *const p_result
){
    assert(p_packet);
    assert(p_iter);
    assert(p_result);

    p_result->m_name = p_iter;

    p_iter = dns_skip_qname(p_packet, p_packet_size, p_iter);

    if ((p_iter == NULL) || ((p_iter + 10) > (p_packet + p_packet_size))) {
        return NULL;
    }

    p_result->m_type        = read_network_u16(p_iter);
    p_result->m_class       = read_network_u16(p_iter + 2);
    p_result->m_data_length = read_network_u16(p_iter + 8);
    p_result->m_data        = p_iter + 10;

    p_iter += 10 + p_result->m_data_length;

    if (p_iter > (p_packet + p_packet_size)) {
        return NULL;
    }

    return p_iter;
}

std::optional<std::string>
dns_decode_qname(
    const char *const p_packet,
    const size_t      p_packet_size,
    const char *      p_iter,
    const bool        p_recurse
){
    assert(p_packet);
    assert(p_iter);

    std::string l_name;

    while (p_iter < (p_packet + p_packet_size)) {
        const uint8_t l_count = *p_iter;

        if (l_count == 0) {
            return std::optional(l_name);
        } else if (l_count > 63) {
            if ((p_iter + 2) >= (p_packet + p_packet_size)) {
                return std::nullopt;
            } else {
                if (p_recurse) {
                    const uint16_t l_offset = read_network_u16(p_iter)
                        & 0b00111111;

                    return dns_decode_qname(
                        p_packet,
                        p_packet_size,
                        p_packet + l_offset,
                        false
                    );
                } else {
                    return std::nullopt;
                }
            }
        } 

        p_iter++;

        if ((p_iter + l_count) > (p_packet + p_packet_size)) {
            return std::nullopt;
        }

        l_name += std::string(p_iter, l_count) + ".";

        p_iter += l_count;
    }

    return std::nullopt;
}

uint16_t
read_network_u16(const char *const l_buffer)
{
    assert(l_buffer);

    return ntohs(*((uint16_t *)l_buffer));
}
