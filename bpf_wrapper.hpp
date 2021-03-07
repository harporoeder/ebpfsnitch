#pragma once

#include <string>
#include <memory>
#include <functional>

#include <bpf/libbpf.h>
#include <spdlog/spdlog.h>

class bpf_wrapper_ring {
public:
    bpf_wrapper_ring(
        const int                                          p_fd,
        const std::function<void(void *const , const int)> p_cb
    );

    ~bpf_wrapper_ring();

    void poll(const int p_timeout_ms);

private:
    struct ring_buffer *m_ring;

    static int
    cb_proxy(
        void *const  p_cb_cookie,
        void *const  p_data,
        const size_t p_data_size
    );

    const std::function<void(void *const , const int)> m_cb;
};

class bpf_wrapper_object {
public:
    bpf_wrapper_object(
        std::shared_ptr<spdlog::logger> p_log,
        const std::string              &p_object_path
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
    const std::unique_ptr<struct bpf_object, void(*)(struct bpf_object *)>
        m_object;

    std::shared_ptr<spdlog::logger> m_log;

    std::vector<struct bpf_link *> m_links;
};
