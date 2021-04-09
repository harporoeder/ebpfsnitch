#include <thread>
#include <chrono>
#include <iostream>

#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>

#include "stopper.hpp"

static void
test_stopper_await_stop_block()
{
    stopper l_stopper;

    std::thread l_thread([&](){
        // technically a race but hard to work around
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        l_stopper.stop();
    });

    l_stopper.await_stop_block();

    l_thread.join();
}

static void
test_stopper_stop_fd()
{
    stopper l_stopper;

    std::thread l_thread([&](){
        // technically a race but hard to work around
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        l_stopper.stop();
    });

    fd_set l_fd_set;

    FD_ZERO(&l_fd_set);

    FD_SET(l_stopper.get_stop_fd(), &l_fd_set);
    assert(select(l_stopper.get_stop_fd() + 1, &l_fd_set, NULL, &l_fd_set, NULL) == 1);

    l_thread.join();
}

int
main()
{
    test_stopper_await_stop_block();
    test_stopper_stop_fd();

    return 0;
}
