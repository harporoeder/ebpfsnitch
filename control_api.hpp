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

    typedef std::function<void (std::shared_ptr<session>)> on_connect_fn_t;

    class session :
        public  std::enable_shared_from_this<session>,
        private boost::noncopyable
    {
    public:
        typedef std::function<void (nlohmann::json)> on_message_fn_t;
        typedef std::function<void ()>               on_disconnect_fn_t;

        // limited friend access
        class key {
        private:
            friend class control_api;

            key() = default;
        };

        session(
            key                             p_key,
            boost::asio::io_service        &p_service,
            std::shared_ptr<spdlog::logger> p_log
        );

        ~session();

        void start(key p_key);

        boost::asio::local::stream_protocol::socket &get_socket(key p_key);

        void queue_outgoing_json(const nlohmann::json p_message);

        void set_on_message_cb(on_message_fn_t p_cb);

        void set_on_disconnect_cb(on_disconnect_fn_t p_cb);

    private:
        boost::asio::local::stream_protocol::socket m_socket;
        boost::asio::io_service                    &m_service;
        const std::shared_ptr<spdlog::logger>       m_log;
        boost::asio::streambuf                      m_buffer;
        std::deque<nlohmann::json>                  m_outgoing;

        std::optional<on_message_fn_t>    m_on_message;
        std::optional<on_disconnect_fn_t> m_on_disconnect;

        void handle_reads();
        void handle_writes();
        void handle_disconnect();
    };

    control_api(
        std::shared_ptr<spdlog::logger> p_log,
        std::optional<std::string>      p_group,
        on_connect_fn_t                 p_on_connect
    );

    ~control_api();

private:
    const std::shared_ptr<spdlog::logger> m_log;
    const on_connect_fn_t                 m_on_connect;

    boost::asio::io_service                                        m_service;
    std::unique_ptr<boost::asio::local::stream_protocol::acceptor> m_acceptor;
    std::thread                                                    m_thread;

    void accept();
    void thread();
};