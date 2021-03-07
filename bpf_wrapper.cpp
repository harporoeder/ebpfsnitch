#include <stdexcept>

#include "bpf_wrapper.hpp"

bpf_wrapper_object::bpf_wrapper_object(
    std::shared_ptr<spdlog::logger> p_log,
    const std::string              &p_object_path
):
    m_log(p_log),
    m_object(bpf_object__open(p_object_path.c_str()), bpf_object__close)
{
    if (m_object == NULL) {
        throw std::runtime_error("bpf_object__open failed " + p_object_path);
    }

    if (bpf_object__load(m_object.get()) != 0) {
        throw std::runtime_error("m_object__load() failed");
    }
}

bpf_wrapper_object::~bpf_wrapper_object()
{
    for (const auto &l_link : m_links) {
        bpf_link__disconnect(l_link);

        if (bpf_link__destroy(l_link) != 0) {
            m_log->error("bpf_link__destroy() failed");
        }
    }

    if (bpf_object__unload(m_object.get()) != 0) {
        m_log->error("bpf_object__unload() failed");
    }
}

void
bpf_wrapper_object::attach_kprobe(
    const std::string &p_in_bfp_name,
    const std::string &p_in_kernel_name,
    const bool         p_is_ret_probe
){
    struct bpf_program *const l_hook = bpf_object__find_program_by_name(
        m_object.get(),
        p_in_bfp_name.c_str()
    );

    if (l_hook == NULL) {
        throw std::runtime_error("bpf_object__find_program_by_name() failed");
    }

    struct bpf_link *const l_link = bpf_program__attach_kprobe(
        l_hook,
        p_is_ret_probe,
        p_in_kernel_name.c_str()
    );

    if (l_link == NULL) {
        throw std::runtime_error("bpf_program__attach_kprobe");
    }

    m_links.push_back(l_link);
}

int
bpf_wrapper_object::lookup_map_fd_by_name(const std::string &p_name)
{
    const int l_fd = bpf_object__find_map_fd_by_name(
        m_object.get(),
        p_name.c_str()
    );

    if (l_fd < 0) {
        throw std::runtime_error("bpf_object__find_map_fd_by_name() failed");
    }

    return l_fd;
}