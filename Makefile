main: main.cpp ebpfsnitch_daemon.hpp
	clang++ -D SPDLOG_FMT_EXTERNAL -std=c++17 -o main main.cpp -g3 -lbcc -lnetfilter_queue -lpthread -lspdlog -lfmt

clean:
	rm main