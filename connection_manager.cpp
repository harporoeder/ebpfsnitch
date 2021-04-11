#include <stdexcept>

#include "connection_manager.hpp"
 
connection_manager::connection_manager():
    m_thread(&connection_manager::reaper_thread, this)
{}

connection_manager::~connection_manager()
{
    m_stopper.stop();

    m_thread.join();
}

std::string
connection_manager::make_key(
    const ip_protocol_t p_protocol,
    const bool          p_v6,
    const __uint128_t   p_source_address,
    const __uint128_t   p_destination_address,
    const uint16_t      p_source_port,
    const uint16_t      p_destination_port
){
    std::string l_key;

    l_key.reserve(
        sizeof(p_protocol) +
        sizeof(p_v6) +
        sizeof(p_source_address) +
        sizeof(p_destination_address) +
        sizeof(p_source_port) +
        sizeof(p_destination_port)
    );

    l_key.append((char *)&p_protocol, sizeof(p_protocol));
    l_key.append((char *)&p_v6, sizeof(p_v6));

    l_key.append(
        (char *)&p_source_address,
        sizeof(p_source_address)
    );

    l_key.append(
        (char *)&p_destination_address,
        sizeof(p_destination_address)
    );

    l_key.append(
        (char *)&p_source_port,
        sizeof(p_source_port)
    );

    l_key.append(
        (char *)&p_destination_port,
        sizeof(p_destination_port)
    );

    return l_key;
}

std::shared_ptr<const struct process_info_t>
connection_manager::lookup_connection_info(const nfq_event_t &p_event)
{
    const __uint128_t l_source_address = p_event.m_v6 ?
        p_event.m_source_address_v6 : p_event.m_source_address;

    const __uint128_t l_destination_address = p_event.m_v6 ?
        p_event.m_destination_address_v6 : p_event.m_destination_address;

    const std::string l_key = make_key(
        p_event.m_protocol,
        p_event.m_v6,
        l_source_address,
        l_destination_address,
        p_event.m_source_port,
        p_event.m_destination_port
    );

    std::lock_guard<std::mutex> l_guard(m_lock);

    const auto l_iter = m_mapping.find(l_key);

    if (l_iter != m_mapping.end()) {
        l_iter->second.m_last_active = std::chrono::steady_clock::now();

        return l_iter->second.m_process;
    } else {
        const std::string l_key2 = make_key(
            p_event.m_protocol,
            p_event.m_v6,
            0,
            l_destination_address,
            p_event.m_source_port,
            p_event.m_destination_port
        );

        const auto l_iter2 = m_mapping.find(l_key2);

        if (l_iter2 != m_mapping.end()) {
            l_iter2->second.m_last_active = std::chrono::steady_clock::now();

            return l_iter2->second.m_process;
        } else {
            return nullptr;
        }
    }
}

void
connection_manager::add_connection_info(
    const ebpf_event_t &                  p_event,
    std::shared_ptr<const process_info_t> p_process
) {
    const __uint128_t l_source_address = p_event.m_v6 ?
        p_event.m_source_address_v6 : p_event.m_source_address;

    const __uint128_t l_destination_address = p_event.m_v6 ?
        p_event.m_destination_address_v6 : p_event.m_destination_address;

    const std::string l_key = make_key(
        static_cast<ip_protocol_t>(p_event.m_protocol),
        p_event.m_v6,
        l_source_address,
        l_destination_address,
        p_event.m_source_port,
        p_event.m_destination_port
    );

    std::lock_guard<std::mutex> l_guard(m_lock);

    m_mapping[l_key] = item_t{
        .m_last_active = std::chrono::steady_clock::now(),
        .m_process     = p_process
    };
}

void
connection_manager::reap()
{
    const auto l_now = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> l_guard(m_lock);

    std::erase_if(m_mapping, [&](const auto &l_iter) {
        return (l_now - l_iter.second.m_last_active) >
            std::chrono::seconds{60 * 5};
    }); 
}

void
connection_manager::reaper_thread()
{
    while (!m_stopper.await_stop_for_milliseconds(1000)) {
        reap();
    }
}