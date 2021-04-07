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

private:
    std::mutex              m_lock;
    std::condition_variable m_condition;
    bool                    m_stop_state;
};
