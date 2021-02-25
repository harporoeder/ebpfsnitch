#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <thread>
#include <arpa/inet.h>
#include <unordered_map>
#include <mutex>
#include <assert.h>
#include <algorithm>
#include <condition_variable>
#include <poll.h>
#include <sys/un.h>
#include <nlohmann/json.hpp>
#include <exception>

#include <sys/resource.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "ebpfsnitch_daemon.hpp"

std::shared_ptr<spdlog::logger> g_log;

std::shared_ptr<ebpfsnitch_daemon> g_daemon;
std::condition_variable g_shutdown;
std::mutex g_shutdown_mutex;

static void
signal_handler(const int p_sig);

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

void
signal_handler(const int p_sig)
{
    g_log->info("signal_handler");

    g_daemon.reset();

    g_shutdown.notify_all();
}

static void
signal_pipe(const int p_sig)
{
    g_log->error("SIGPIPE");
}

static
void set_rlimit()
{
    struct rlimit rlim_new = {
        .rlim_cur	= RLIM_INFINITY,
        .rlim_max	= RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        std::cout << "failed to set limits" << std::endl;
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

    g_daemon = std::make_shared<ebpfsnitch_daemon>(g_log);

    std::unique_lock<std::mutex> l_lock(g_shutdown_mutex);
    g_shutdown.wait(l_lock);

    g_log->info("post g_shutdown condition");

    return 0;
}