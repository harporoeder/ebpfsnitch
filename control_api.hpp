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
    class session;

    typedef std::function<nlohmann::json ()>     get_rules_fn_t;
    typedef std::function<void (nlohmann::json)> handle_line_fn_t;
    typedef std::function<void (session &)>      on_connect_fn_t;

    class session :
        public  std::enable_shared_from_this<session>,
        private boost::noncopyable
    {
    public:
        typedef std::function<void (session &, nlohmann::json)> on_message_fn_t;

        // limited friend access
        class key {
        private:
            friend class control_api;

            key() = default;
        };

        boost::asio::local::stream_protocol::socket m_socket;
        boost::asio::streambuf                      m_buffer;
        std::deque<nlohmann::json>                  m_outgoing;

        session(
            key                             p_key,
            boost::asio::io_service        &p_service,
            control_api                    &p_parent,
            std::shared_ptr<spdlog::logger> p_log
        );

        void start(key p_key);

        void queue_outgoing_json(const nlohmann::json &p_message);

        void set_on_message_cb(on_message_fn_t p_cb);

    private:
        control_api                          &m_parent;
        const std::shared_ptr<spdlog::logger> m_log;

        std::optional<on_message_fn_t> m_on_message;

        void handle_reads();
        void handle_writes();
    };

    control_api(
        std::shared_ptr<spdlog::logger> p_log,
        std::optional<std::string>      p_group,
        get_rules_fn_t                  p_get_rules,
        handle_line_fn_t                p_line_handler
    );

    ~control_api();

    void queue_outgoing_json(const nlohmann::json &p_message);

    void remove_session(std::shared_ptr<session> p_session);

private:
    const std::shared_ptr<spdlog::logger> m_log;
    const get_rules_fn_t                  m_get_rules;
    const handle_line_fn_t                m_handle_line;

    boost::asio::io_service                                        m_service;
    std::unique_ptr<boost::asio::local::stream_protocol::acceptor> m_acceptor;
    std::mutex                                                     m_lock;
    std::set<std::shared_ptr<session>>                             m_sessions;
    std::thread                                                    m_thread;

    void accept();
    void thread();
};