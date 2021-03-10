#pragma once

#include <optional>
#include <memory>
#include <string>
#include <unordered_map>
#include <mutex>

struct process_info_t {
    std::string                m_executable;
    std::optional<std::string> m_container_id;
};

class process_manager {
public:
    process_manager();

    ~process_manager();

    std::shared_ptr<const process_info_t>
    lookup_process_info(const uint32_t p_process_id);

private:
    std::unordered_map<uint32_t, std::shared_ptr<process_info_t>>
        m_process_cache;

    std::mutex m_lock;
};
