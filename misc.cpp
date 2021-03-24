#include <chrono>
#include <fstream>
#include <cstdio>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <boost/bimap.hpp>
#include <boost/container/allocator.hpp>
#include <boost/assign.hpp>

#include "misc.hpp"

uint64_t
nanoseconds()
{
    struct timespec l_timespec;

    clock_gettime(CLOCK_MONOTONIC, &l_timespec);

    return l_timespec.tv_nsec + (l_timespec.tv_sec * 1000000000);
}

std::string
nf_hook_to_string(const nf_hook_t p_hook)
{
    switch (p_hook) {
        case nf_hook_t::IP_PRE_ROUTING:
            return std::string("IP_PRE_ROUTING"); break;
        case nf_hook_t::IP_LOCAL_IN:
            return std::string("IP_LOCAL_IN"); break;
        case nf_hook_t::IP_FORWARD:
            return std::string("IP_FORWARD"); break;
        case nf_hook_t::IP_LOCAL_OUT:
            return std::string("IP_LOCAL_OUT"); break;
        case nf_hook_t::IP_POST_ROUTING:
            return std::string("IP_POST_ROUTING"); break;
    }

    return std::string("unknown");
}

typedef boost::bimaps::bimap<
    ip_protocol_t,
    std::string,
    boost::container::allocator<void>
> g_protocol_map_type;

const g_protocol_map_type g_protocol_map =
    boost::assign::list_of<g_protocol_map_type::relation>
        ( ip_protocol_t::HOPOPT,    "HOPOPT"    )
        ( ip_protocol_t::ICMP,      "ICMP"      )
        ( ip_protocol_t::IGMP,      "IGMP"      )
        ( ip_protocol_t::GGP,       "GGP"       )
        ( ip_protocol_t::IPV4,      "IPV4"      )
        ( ip_protocol_t::ST,        "ST"        )
        ( ip_protocol_t::TCP,       "TCP"       )
        ( ip_protocol_t::CBT,       "CBT"       )
        ( ip_protocol_t::EGP,       "EGP"       )
        ( ip_protocol_t::IGP,       "IGP"       )
        ( ip_protocol_t::BBNRCCMON, "BBNRCCMON" )
        ( ip_protocol_t::NVPII,     "NVPII"     )
        ( ip_protocol_t::PUP,       "PUP"       )
        ( ip_protocol_t::ARGUS,     "ARGUS"     )
        ( ip_protocol_t::EMCON,     "EMCON"     )
        ( ip_protocol_t::XNET,      "XNET"      )
        ( ip_protocol_t::CHAOS,     "CHAOS"     )
        ( ip_protocol_t::UDP,       "UDP"       );

ip_protocol_t
ip_protocol_from_string(const std::string &p_protocol)
{
    return g_protocol_map.right.find(p_protocol)->second;
}

std::string
ip_protocol_to_string(const ip_protocol_t p_protocol)
{
    return g_protocol_map.left.find(p_protocol)->second;
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

void
atomically_write_file(const std::string &p_path, const std::string &p_data)
{
    const std::string l_temp_path = p_path + ".tmp";

    std::ofstream l_stream(l_temp_path);

    if (!l_stream) {
        throw std::runtime_error("std::of_stream() failed");
    }

    l_stream << p_data;

    l_stream.close();

    if (std::rename(l_temp_path.c_str(), p_path.c_str())) {
        throw std::runtime_error("std::rename failed");
    }
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

std::string
ipv6_to_string(const __uint128_t p_address)
{
    char l_buffer[INET6_ADDRSTRLEN];

    const char *const l_status = inet_ntop(
        AF_INET6,
        &p_address,
        l_buffer,
        INET6_ADDRSTRLEN
    );

    if (l_status == NULL) {
        throw std::runtime_error("inet_ntop() failed");
    }

    return std::string(l_buffer);
}
