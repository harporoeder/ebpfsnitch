#pragma once

#include <string>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <array>
#include <chrono>
#include <thread>

#include <boost/functional/hash.hpp>

#include "process_manager.hpp"
#include "nfq_event.h"
#include "ebpf_event.hpp"
#include "stopper.hpp"

struct connection_tuple_t {
    ip_protocol_t m_protocol;
    bool          m_v6;
    __uint128_t   m_source_address;
    __uint128_t   m_destination_address;
    uint16_t      m_source_port;
    uint16_t      m_destination_port;

    bool
    operator == (const connection_tuple_t &p_other) const {
        return ( m_protocol            == p_other.m_protocol            )
            && ( m_v6                  == p_other.m_v6                  )
            && ( m_source_address      == p_other.m_source_address      )
            && ( m_destination_address == p_other.m_destination_address )
            && ( m_source_port         == p_other.m_source_port         )
            && ( m_destination_port    == p_other.m_destination_port    );
    };

    struct hasher {
        std::size_t
        operator() (const connection_tuple_t &p_tuple) const
        {
            std::size_t l_seed = 0;

            boost::hash_combine(
                l_seed,
                boost::hash_value(p_tuple.m_protocol)
            );

            boost::hash_combine(
                l_seed,
                boost::hash_value(p_tuple.m_v6)
            );

            boost::hash_combine(
                l_seed,
                boost::hash_value(p_tuple.m_source_address)
            );

            boost::hash_combine(
                l_seed,
                boost::hash_value(p_tuple.m_destination_address)
            );

            boost::hash_combine(
                l_seed,
                boost::hash_value(p_tuple.m_source_port)
            );

            boost::hash_combine(
                l_seed,
                boost::hash_value(p_tuple.m_destination_port)
            );

            return l_seed;
        }
    };
};

class connection_manager {
public:
    connection_manager();

    ~connection_manager();

    std::shared_ptr<const struct process_info_t>
    lookup_connection_info(const nfq_event_t &p_event);

    void
    add_connection_info(
        const ebpf_event_t &                  p_event,
        std::shared_ptr<const process_info_t> p_process
    );

private:
    void reap();
    void reaper_thread();

    struct item_t {
        std::chrono::time_point<std::chrono::steady_clock> m_last_active;
        std::shared_ptr<const process_info_t>              m_process;
    };

    std::thread m_thread;
    stopper     m_stopper;
    std::mutex  m_lock;

    std::unordered_map<
        connection_tuple_t,
        item_t,
        connection_tuple_t::hasher
    > m_mapping;
};
