all: bin ephemeral-blue.exe

ephemeral-blue.exe:
	x86_64-w64-mingw32-g++ --std=c++20 ephemeral-blue/main.cpp -o bin/eb.exe -static -lwintrust

bin:
	mkdir -p bin
