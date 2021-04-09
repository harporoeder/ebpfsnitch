#pragma once

#include <condition_variable>
#include <mutex>

class stopper {
public:
    stopper();

    ~stopper();

    void stop();

    void await_stop_block();

    bool should_stop();

    bool await_stop_for_milliseconds(const unsigned int m_timeout);

    int get_stop_fd();

private:
    std::mutex              m_lock;
    std::condition_variable m_condition;
    bool                    m_stop_state;
    int                     m_pipe_fd[2];
};
