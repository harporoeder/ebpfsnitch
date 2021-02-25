#pragma once

#include <string>

#include <bpf/libbpf.h>

class bpf_wrapper_object {
public:
    bpf_wrapper_object(const std::string &p_object_path);

    ~bpf_wrapper_object();

    void
    attach_kprobe(
        const std::string &p_in_bfp_name,
        const std::string &p_in_kernel_name,
        const bool         p_is_ret_probe
    );

    struct bpf_object *m_object;
};