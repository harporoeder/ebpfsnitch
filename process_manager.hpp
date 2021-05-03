#pragma once

#include <optional>
#include <memory>
#include <string>
#include <unordered_map>
#include <mutex>
#include <regex>
#include <thread>
#include <functional>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include "stopper.hpp"

struct process_info_t {
    uint32_t                   m_process_id;
    std::string                m_executable;
    std::optional<std::string> m_container_id;
    uint64_t                   m_start_time;
    uint32_t                   m_user_id;
    uint32_t                   m_group_id;

    nlohmann::json to_json() const;
};

class process_manager {
public:
    typedef std::function<void (const process_info_t &)> add_process_cb_t;
    typedef std::function<void (uint32_t)>               remove_process_cb_t;

    process_manager(std::shared_ptr<spdlog::logger> p_log);

    ~process_manager();

    std::shared_ptr<const process_info_t>
    lookup_process_info(const uint32_t p_process_id);

    void set_load_process_cb(add_process_cb_t p_cb);

    void set_remove_process_cb(remove_process_cb_t p_cb);

    nlohmann::json processes_to_json();

private:
    const std::regex m_docker_regex;

    std::unordered_map<uint32_t, std::shared_ptr<process_info_t>>
        m_process_cache;

    std::mutex m_lock;

    std::optional<add_process_cb_t>    m_add_process_cb;
    std::optional<remove_process_cb_t> m_remove_process_cb;

    std::shared_ptr<process_info_t>
    load_process_info(const uint32_t p_process_id);

    uint64_t
    load_process_start_time(const uint32_t p_process_id);

    void
    reap_dead();

    void
    reaper_thread();

    std::shared_ptr<spdlog::logger> m_log;
    stopper                         m_stopper;
    std::thread                     m_thread;
};
