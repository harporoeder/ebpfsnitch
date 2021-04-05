#include "dns_cache.hpp"

dns_cache::dns_cache(){};

dns_cache::~dns_cache(){};

std::optional<std::string>
dns_cache::lookup_domain_v4(const uint32_t p_address)
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    const auto l_iter = m_ipv4_to_domain.find(p_address);

    if (l_iter != m_ipv4_to_domain.end()) {
        return std::optional<std::string>(l_iter->second);
    } else {
        return std::nullopt;
    }
}

std::optional<std::string>
dns_cache::lookup_domain_v6(const __uint128_t p_address)
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    const auto l_iter = m_ipv6_to_domain.find(p_address);

    if (l_iter != m_ipv6_to_domain.end()) {
        return std::optional<std::string>(l_iter->second);
    } else {
        return std::nullopt;
    }
}

void
dns_cache::add_ipv4_mapping(uint32_t p_address, std::string p_domain)
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    m_ipv4_to_domain[p_address] = p_domain;
}

void
dns_cache::add_ipv6_mapping(__uint128_t p_address, std::string p_domain)
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    m_ipv6_to_domain[p_address] = p_domain;
}
