#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <array>
#include <chrono>
#include <thread>

#include "process_manager.hpp"
#include "nfq_event.h"
#include "ebpf_event.hpp"
#include "stopper.hpp"

class connection_manager {
public:
    connection_manager();

    ~connection_manager();

    std::shared_ptr<const struct process_info_t>
    lookup_connection_info(const nfq_event_t &p_event);

    void
    add_connection_info(
        const ebpf_event_t &            p_event,
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
    void reap();
    void reaper_thread();

    struct item_t {
        std::chrono::time_point<std::chrono::steady_clock> m_last_active;
        std::shared_ptr<const process_info_t>              m_process;
    };

    std::thread                             m_thread;
    stopper                                 m_stopper;
    std::mutex                              m_lock;
    std::unordered_map<std::string, item_t> m_mapping;
};
