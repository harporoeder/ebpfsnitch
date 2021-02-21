cmake_minimum_required (VERSION 3.0.2)

# GCC bug
set( CMAKE_C_COMPILER   "clang"   )
set( CMAKE_CXX_COMPILER "clang++" )

project (ebpfsnitch)

set (CMAKE_CXX_STANDARD 17)

add_executable (main main.cpp ebpfsnitch_daemon.cpp rule_engine.cpp misc.cpp)

target_compile_definitions(main PRIVATE SPDLOG_FMT_EXTERNAL)

target_link_libraries (main PRIVATE
    bcc netfilter_queue pthread spdlog fmt
)

target_link_libraries (main)

file(
    COPY ${CMAKE_CURRENT_SOURCE_DIR}/probes.c
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
)
