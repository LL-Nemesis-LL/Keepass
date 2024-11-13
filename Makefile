OUT = main

SRC = src/*.cpp main.cpp
CFLAGS = -Wall -Wextra -std=c++17
CC = g++

$(OUT): 
	$(CC) $(CFLAGS) $(SRC) -o $(OUT)

run: $(OUT)
	./${OUT}