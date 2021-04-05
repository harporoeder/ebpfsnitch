#include "dns_cache.hpp"

dns_cache::dns_cache():
    m_ipv4_to_domain(1000),
    m_ipv6_to_domain(1000)
{};

dns_cache::~dns_cache(){};

std::optional<std::string>
dns_cache::lookup_domain_v4(const uint32_t p_address)
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    return m_ipv4_to_domain.lookup(p_address);
}

std::optional<std::string>
dns_cache::lookup_domain_v6(const __uint128_t p_address)
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    return m_ipv6_to_domain.lookup(p_address);
}

void
dns_cache::add_ipv4_mapping(uint32_t p_address, std::string p_domain)
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    m_ipv4_to_domain.insert(p_address, p_domain);
}

void
dns_cache::add_ipv6_mapping(__uint128_t p_address, std::string p_domain)
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    m_ipv6_to_domain.insert(p_address, p_domain);
}
