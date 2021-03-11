cmake_minimum_required(VERSION 3.0.2)

# GCC bug
set(CMAKE_C_COMPILER   "clang")
set(CMAKE_CXX_COMPILER "clang++")

project(ebpfsnitch)

set(CMAKE_CXX_STANDARD 20)

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

add_custom_command(
    OUTPUT
        probes_compiled.h
    COMMAND
        cd ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/probes.dir &&
            xxd -i probes.c.o > ${CMAKE_CURRENT_BINARY_DIR}/probes_compiled.h
)

# daemon target ----------------------------------------------------------------

find_package( Boost REQUIRED COMPONENTS system program_options )

add_executable(
    ebpfsnitch
    main.cpp
    ebpfsnitch_daemon.cpp
    rule_engine.cpp
    misc.cpp
    bpf_wrapper.cpp
    nfq_wrapper.cpp
    dns_parser.cpp
    process_manager.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/probes_compiled.h
)

target_compile_options(
    ebpfsnitch
    PRIVATE
        -W
)

target_compile_definitions(ebpfsnitch PRIVATE SPDLOG_FMT_EXTERNAL)

target_include_directories(
    ebpfsnitch
    PRIVATE
        ${Boost_INCLUDE_DIRS}
        ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(
    ebpfsnitch
    PRIVATE
        bpf
        netfilter_queue
        pthread
        spdlog
        fmt
        nfnetlink
        mnl
        ${Boost_LIBRARIES}
)
