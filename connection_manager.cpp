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

std::shared_ptr<const struct process_info_t>
connection_manager::lookup_connection_info(const nfq_event_t &p_event)
{
    const __uint128_t l_source_address = p_event.m_v6 ?
        p_event.m_source_address_v6 : p_event.m_source_address;

    const __uint128_t l_destination_address = p_event.m_v6 ?
        p_event.m_destination_address_v6 : p_event.m_destination_address;

    connection_tuple_t l_key = {
        .m_protocol            = static_cast<ip_protocol_t>(p_event.m_protocol),
        .m_v6                  = p_event.m_v6,
        .m_source_address      = l_source_address,
        .m_destination_address = l_destination_address,
        .m_source_port         = p_event.m_source_port,
        .m_destination_port    = p_event.m_destination_port
    };

    std::lock_guard<std::mutex> l_guard(m_lock);

    const auto l_iter = m_mapping.find(l_key);

    if (l_iter != m_mapping.end()) {
        l_iter->second.m_last_active = std::chrono::steady_clock::now();

        return l_iter->second.m_process;
    } else {
        l_key.m_source_address = 0;

        const auto l_iter2 = m_mapping.find(l_key);

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

    const connection_tuple_t l_key = {
        .m_protocol            = static_cast<ip_protocol_t>(p_event.m_protocol),
        .m_v6                  = p_event.m_v6,
        .m_source_address      = l_source_address,
        .m_destination_address = l_destination_address,
        .m_source_port         = p_event.m_source_port,
        .m_destination_port    = p_event.m_destination_port
    };

    const item_t l_item = {
        .m_last_active = std::chrono::steady_clock::now(),
        .m_process     = p_process
    };

    std::lock_guard<std::mutex> l_guard(m_lock);

    m_mapping[l_key] = l_item;
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
