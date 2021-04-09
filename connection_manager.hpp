#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <array>

#include "process_manager.hpp"
#include "nfq_event.h"
#include "probe_event.hpp"

class connection_manager {
public:
    connection_manager();

    ~connection_manager();

    std::shared_ptr<const struct process_info_t>
    lookup_connection_info(const nfq_event_t &p_event);

    void
    add_connection_info(
        const probe_ipv4_event_t &            p_event,
        std::shared_ptr<const process_info_t> p_process
    );

    static std::string
    make_key(
        const ip_protocol_t p_protocol,
        const bool          p_v6,
        const __uint128_t   p_source_address,
        const __uint128_t   p_destination_address,
        const uint16_t      p_source_port,
        const uint16_t      p_destination_port
    );

private:
    std::mutex m_lock;

    std::unordered_map<std::string, std::shared_ptr<const process_info_t>>
        m_mapping;
};
