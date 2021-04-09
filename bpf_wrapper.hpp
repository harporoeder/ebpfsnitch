#pragma once

#include <string>
#include <memory>

#include <spdlog/spdlog.h>

class bpf_wrapper_ring {
public:
    bpf_wrapper_ring(
        const int                                          p_fd,
        const std::function<void(void *const , const int)> p_cb
    );

    ~bpf_wrapper_ring();

    void poll(const int p_timeout_ms);

    void consume();

    int get_fd();

private:
    class impl;

    const std::unique_ptr<impl> m_impl;
};

class bpf_wrapper_object {
public:
    bpf_wrapper_object(
        std::shared_ptr<spdlog::logger> p_log,
        const std::string              &p_object
    );

    ~bpf_wrapper_object();

    void
    attach_kprobe(
        const std::string &p_in_bfp_name,
        const std::string &p_in_kernel_name,
        const bool         p_is_ret_probe
    );

    int
    lookup_map_fd_by_name(const std::string &p_name);

private:
    class impl;

    const std::unique_ptr<impl> m_impl;
};
