main: main.cpp
	clang++ -std=c++14 -o main main.cpp -g3 -lbcc -lnetfilter_queue -lpthread

clean:
	rm main