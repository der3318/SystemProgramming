CC = gcc
CXX = g++
CFLAGS = -O2 -std=c99 -Wall
CXXFLAGS = -O2 -std=c++11 -Wall
TARGET = vowel_count

all: $(TARGET)

%: %.c
	$(CC) $(CFLAGS) $< -o $@

%: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm $(TARGET) -rf

