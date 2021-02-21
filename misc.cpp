#include <chrono>
#include <fstream>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "misc.hpp"

uint64_t
nanoseconds()
{
    struct timespec l_timespec;

    clock_gettime(CLOCK_MONOTONIC, &l_timespec);

    return l_timespec.tv_nsec + (l_timespec.tv_sec * 1000000000);
}

std::string
ip_protocol_to_string(const ip_protocol_t p_protocol)
{
    switch (p_protocol) {
        case ip_protocol_t::ICMP: return std::string("ICMP"); break;
        case ip_protocol_t::TCP:  return std::string("TCP");  break;
        case ip_protocol_t::UDP:  return std::string("UDP");  break;
    }

    return std::string("unknown");
}

std::string
file_to_string(const std::string &p_path) {
    std::ifstream l_stream(p_path);

    if (l_stream.is_open() == false) {
        throw std::runtime_error("std::ifstream() failed");
    }

    return std::string(
        (std::istreambuf_iterator<char>(l_stream)),
        std::istreambuf_iterator<char>()
    );
}

std::string
ipv4_to_string(const uint32_t p_address)
{
    char l_buffer[INET_ADDRSTRLEN];

    const char *const l_status = inet_ntop(
        AF_INET,
        &p_address,
        l_buffer,
        INET_ADDRSTRLEN
    );

    if (l_status == NULL) {
        throw std::runtime_error("inet_ntop() failed");
    }

    return std::string(l_buffer);
}