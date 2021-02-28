cmake_minimum_required(VERSION 3.0.2)

# GCC bug
set(CMAKE_C_COMPILER   "clang")
set(CMAKE_CXX_COMPILER "clang++")

project(ebpfsnitch)

set(CMAKE_CXX_STANDARD 17)

# eBPF target ------------------------------------------------------------------

add_custom_command(
    OUTPUT
        vmlinux.h
    COMMAND
        bpftool btf dump file /sys/kernel/btf/vmlinux format c >
            ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
)

add_library(
    probes
    OBJECT
        probes.c
        ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
)

target_include_directories(
    probes
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
)

target_compile_options(
    probes
    PRIVATE
        -O2 -target bpf
)

# daemon target ----------------------------------------------------------------

find_package( Boost REQUIRED COMPONENTS system program_options )

add_executable(
    main
    main.cpp
    ebpfsnitch_daemon.cpp
    rule_engine.cpp
    misc.cpp
    bpf_wrapper.cpp
)

target_compile_definitions(main PRIVATE SPDLOG_FMT_EXTERNAL)

target_include_directories(
    main
    PRIVATE
        ${Boost_INCLUDE_DIRS}
)

target_link_libraries(
    main
    PRIVATE
        bpf
        netfilter_queue
        pthread
        spdlog
        fmt
        nfnetlink
        ${Boost_LIBRARIES}
)
