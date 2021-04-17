#pragma once

#include <deque>
#include <set>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <optional>
#include <functional>
#include <unordered_map>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <boost/core/noncopyable.hpp>
#include <boost/asio.hpp>

class control_api : private boost::noncopyable {
public:
    control_api(
        std::shared_ptr<spdlog::logger> p_log,
        std::optional<std::string>      p_group,
        std::function<nlohmann::json()> p_get_rules
    );

    ~control_api();

    void queue_outgoing_json(const nlohmann::json &p_message);

private:
    struct session : private boost::noncopyable {
        session(boost::asio::io_service &p_service);

        boost::asio::local::stream_protocol::socket m_socket;
        boost::asio::streambuf                      m_buffer;
        std::deque<nlohmann::json>                  m_outgoing;
    };

    const std::shared_ptr<spdlog::logger>                          m_log;
    const std::function<nlohmann::json()>                          m_get_rules;
    boost::asio::io_service                                        m_service;
    std::unique_ptr<boost::asio::local::stream_protocol::acceptor> m_acceptor;
    std::mutex                                                     m_lock;
    std::set<std::shared_ptr<session>>                             m_sessions;
    std::thread                                                    m_thread;

    void accept();
    void initial(std::shared_ptr<session> p_session);
    void handle_reads(std::shared_ptr<session> p_session);
    void handle_writes(std::shared_ptr<session> p_session);
    void remove_session(std::shared_ptr<session> p_session);
    void thread();
};
