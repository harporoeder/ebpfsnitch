#include "stopper.hpp"

stopper::stopper(): m_stop_state(false) {}

stopper::~stopper(){}

void
stopper::stop()
{
    {
        std::unique_lock<std::mutex> l_guard(m_lock);

        m_stop_state = true;
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
