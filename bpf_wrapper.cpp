#include <stdexcept>

#include "bpf_wrapper.hpp"

bpf_wrapper_object::bpf_wrapper_object(const std::string &p_object_path)
{
    m_object = bpf_object__open(p_object_path.c_str());

    if (m_object == NULL) {
        throw std::runtime_error("bpf_object__open failed " + p_object_path);
    }

    if (bpf_object__load(m_object) != 0) {
        throw std::runtime_error("m_object__load() failed");
    }
}

bpf_wrapper_object::~bpf_wrapper_object()
{
    bpf_object__unload(m_object);
}

void
bpf_wrapper_object::attach_kprobe(
    const std::string &p_in_bfp_name,
    const std::string &p_in_kernel_name,
    const bool         p_is_ret_probe
){
    struct bpf_program *const l_hook = bpf_object__find_program_by_name(
        m_object,
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
}