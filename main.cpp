#include <exception>
#include <iostream>

#include <signal.h>
#include <sys/resource.h>

#include <boost/program_options.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "ebpfsnitch_daemon.hpp"

std::shared_ptr<spdlog::logger>    g_log;
std::unique_ptr<ebpfsnitch_daemon> g_daemon;

/*
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
*/

static void
signal_stop(const int p_sig)
{
    g_log->info("signal_stop {}", p_sig);

    g_daemon->shutdown();
}

static void
signal_pipe(const int p_sig)
{
    (void)p_sig;

    g_log->error("SIGPIPE");
}

static void
set_limits()
{
    struct rlimit l_limit = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &l_limit)) {
        throw std::runtime_error("failed to set limits");
    }
}

int
main(const int p_argc, const char** p_argv)
{
    g_log = spdlog::stdout_color_mt("console");
    g_log->set_level(spdlog::level::trace);

    try {
        boost::program_options::options_description
            l_description("eBPFSnitch Allowed options");

        l_description.add_options()
            ( "help,h",       "produce help message"          )
            ( "version,v",    "print version"                 )
            ( "remove-rules", "remove iptables rules"         )
            (
                "group",
                boost::program_options::value<std::string>(),
                "group name for control socket"
            )
            (
                "rules-path",
                boost::program_options::value<std::string>(),
                "file to load / store firewall rules"
            );

        boost::program_options::variables_map l_map;

        boost::program_options::store(
            boost::program_options::parse_command_line(
                p_argc,
                p_argv,
                l_description
            ),
            l_map
        );

        boost::program_options::notify(l_map);

        if (l_map.count("help")) {
            std::cout << l_description;

            return 0;
        }

        if (l_map.count("version")) {
            std::cout << "0.2.0" << std::endl;

            return 0;
        }

        if (l_map.count("remove-rules")) {
            iptables_raii::remove_rules();

            return 0;
        }

        const std::optional<std::string> l_group = [&](){
            if (l_map.count("group")) {
                return std::optional(l_map["group"].as<std::string>());
            } else {
                return std::optional<std::string>();
            }
        }();

        const std::optional<std::string> l_rules_path = [&](){
            if (l_map.count("rules-path")) {
                return std::optional(l_map["rules-path"].as<std::string>());
            } else {
                return std::optional<std::string>();
            }
        }();

        signal(SIGPIPE, signal_pipe);

        set_limits();

        g_daemon = std::make_unique<ebpfsnitch_daemon>(
            g_log,
            l_group,
            l_rules_path
        );

        signal(SIGINT, signal_stop);
        signal(SIGTERM, signal_stop); 

        g_daemon->await_shutdown();
    } catch (const std::exception &p_error) {
        g_log->error("main() exception: {}", p_error.what());

        return 1;
    }

    return 0;
}
