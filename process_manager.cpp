#include <unistd.h>

#include "misc.hpp"
#include "process_manager.hpp"

process_manager::process_manager():
    m_docker_regex(".*/docker/(\\w+)\n")
{}

process_manager::~process_manager(){}

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
    } catch (...) {}

    return std::make_shared<struct process_info_t>(l_process_info);
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