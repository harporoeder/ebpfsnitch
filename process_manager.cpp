#include <iostream>
#include <chrono>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <spdlog/spdlog.h>

#include <unistd.h>

#include "misc.hpp"
#include "process_manager.hpp"

process_manager::process_manager(std::shared_ptr<spdlog::logger> p_log):
    m_docker_regex(".*/docker/(\\w+)\n"),
    m_log(p_log),
    m_shutdown(false),
    m_thread(&process_manager::reaper_thread, this)
{}

process_manager::~process_manager()
{
    m_shutdown.store(true);

    m_thread.join();
}

std::shared_ptr<process_info_t>
process_manager::load_process_info(const uint32_t p_process_id)
{
    const std::string l_path = 
        "/proc/" +
        std::to_string(p_process_id) +
        "/exe";

    char l_readlink_buffer[1024 * 32];

    const ssize_t l_readlink_status = readlink(
        l_path.c_str(),
        l_readlink_buffer,
        sizeof(l_readlink_buffer) - 1
    );

    if (l_readlink_status == -1) {
        return nullptr;
    }

    l_readlink_buffer[l_readlink_status] = '\0';

    const std::string l_path_cgroup = 
        "/proc/" +
        std::to_string(p_process_id) +
        "/cgroup";

    process_info_t l_process_info;

    l_process_info.m_executable   = std::string(l_readlink_buffer);
    l_process_info.m_container_id = std::nullopt;

    try {
        const std::string l_cgroup = file_to_string(l_path_cgroup);

        l_process_info.m_start_time = load_process_start_time(p_process_id);

        std::smatch l_match;

        if (std::regex_search(
            l_cgroup.begin(),
            l_cgroup.end(),
            l_match,
            m_docker_regex)
        ){
            l_process_info.m_container_id =
                std::optional<std::string>(l_match[1]);
        }
    } catch (const std::exception &err) {
        return nullptr;
    }

    return std::make_shared<struct process_info_t>(l_process_info);
}

uint64_t
process_manager::load_process_start_time(const uint32_t p_process_id)
{
    const std::string l_path = 
        "/proc/" +
        std::to_string(p_process_id) +
        "/stat";

    const std::string l_stat = file_to_string(l_path);

    std::vector<std::string> l_segments;

    boost::split(
        l_segments,
        l_stat,
        boost::is_any_of(" "),
        boost::token_compress_on
    );

    if (l_segments.size() < 22) {
        throw std::runtime_error("parse /proc failed");
    }

    return boost::lexical_cast<uint64_t>(l_segments[21]);
}

std::shared_ptr<const process_info_t>
process_manager::lookup_process_info(const uint32_t p_process_id)
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    const auto l_iter = m_process_cache.find(p_process_id);

    if (l_iter != m_process_cache.end()) {
        return l_iter->second;
    }

    const std::shared_ptr<process_info_t> l_process =
        load_process_info(p_process_id);

    if (l_process == nullptr) {
        return nullptr;
    }

    m_process_cache[p_process_id] = l_process;

    return l_process;
}

void
process_manager::reap_dead()
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    const auto l_count = std::erase_if(m_process_cache, 
        [&](const auto &l_process) {
            try {
                if (
                    l_process.second->m_start_time ==
                    load_process_start_time(l_process.first)
                ) {
                    return false;
                }
            } catch (...) {}

            m_log->info("filtering process {}", l_process.first);

            return true;
        }
    );
}

void
process_manager::reaper_thread()
{
    while (!m_shutdown.load()) {
        reap_dead();

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}