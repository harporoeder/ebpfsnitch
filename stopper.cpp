#include <unistd.h>

#include "stopper.hpp"

stopper::stopper(): m_stop_state(false)
{
    if (pipe(m_pipe_fd) == -1) {
        throw std::runtime_error("pipe() failed");
    }
}

stopper::~stopper()
{
    stop();

    close(m_pipe_fd[0]);
}

void
stopper::stop()
{
    {
        std::unique_lock<std::mutex> l_guard(m_lock);

        if (m_stop_state == false) {
            m_stop_state = true;

            close(m_pipe_fd[1]);
        }
    }

    m_condition.notify_all();
}

void
stopper::await_stop_block()
{
    std::unique_lock<std::mutex> l_guard(m_lock);

    if (m_stop_state == true) {
        return;
    }

    m_condition.wait(l_guard);
}

bool
stopper::should_stop()
{
    std::lock_guard<std::mutex> l_guard(m_lock);

    return m_stop_state;
}

bool
stopper::await_stop_for_milliseconds(const unsigned int m_timeout)
{
    std::unique_lock<std::mutex> l_guard(m_lock);

    if (m_stop_state == true) {
        return true;
    }

    m_condition.wait_for(l_guard, std::chrono::milliseconds(m_timeout));

    return m_stop_state;
}

int
stopper::get_stop_fd()
{
    return m_pipe_fd[0];
}