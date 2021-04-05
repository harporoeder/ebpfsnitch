#pragma once

#include <mutex>
#include <optional>
#include <unordered_map>

#include "lru_map.hpp"

class dns_cache {
public:
    dns_cache();

    ~dns_cache();

    std::optional<std::string>
    lookup_domain_v4(const uint32_t p_address);

    std::optional<std::string>
    lookup_domain_v6(const __uint128_t p_address);

    void add_ipv4_mapping(uint32_t p_address, std::string p_domain);

    void add_ipv6_mapping(__uint128_t p_address, std::string p_domain);

private:
    std::mutex m_lock;

    lru_map<uint32_t, std::string>    m_ipv4_to_domain;
    lru_map<__uint128_t, std::string> m_ipv6_to_domain;
};
