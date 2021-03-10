#pragma once

#include <optional>
#include <memory>
#include <string>

struct process_info_t {
    std::string                m_executable;
    std::optional<std::string> m_container_id;
};

class process_manager {
public:
    process_manager();

    ~process_manager();

    std::shared_ptr<process_info_t>
    lookup_process_info(const uint32_t p_process_id);

private:
};
