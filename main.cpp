#include <fstream>
#include <mutex>
#include <condition_variable>
#include <exception>

#include <signal.h>
#include <sys/resource.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "ebpfsnitch_daemon.hpp"

std::shared_ptr<spdlog::logger> g_log;
std::condition_variable         g_shutdown;
std::mutex                      g_shutdown_mutex;

static void
trace_ebpf()
{
    std::ifstream l_pipe("/sys/kernel/debug/tracing/trace_pipe");
    std::string l_line;

    while (true) {
        if (std::getline(l_pipe, l_line)) {
            g_log->trace("eBPF log: {}", l_line);
        } else {
            sleep(1);
        }
    }
}

static void
signal_handler(const int p_sig)
{
    g_log->info("signal_handler");

    g_shutdown.notify_all();
}

static void
signal_pipe(const int p_sig)
{
    g_log->error("SIGPIPE");
}

static void
set_rlimit()
{
    struct rlimit rlim_new = {
        .rlim_cur	= RLIM_INFINITY,
        .rlim_max	= RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        g_log->error("failed to set limits");
    }
}


int
main()
{
    g_log = spdlog::stdout_color_mt("console");
    g_log->set_level(spdlog::level::trace);

    set_rlimit();

    signal(SIGINT, signal_handler); 
    signal(SIGPIPE, signal_pipe);

    try {
        const auto l_daemon = std::make_shared<ebpfsnitch_daemon>(g_log);

        std::unique_lock<std::mutex> l_lock(g_shutdown_mutex);
        g_shutdown.wait(l_lock);

        g_log->info("post g_shutdown condition");
    } catch (const std::exception &p_error) {
        g_log->error("exception: {}", p_error.what());

        return 1;
    }

    return 0;
}