OUT = main

SRC = src/*.cpp main.cpp
CFLAGS = -Wall -Wextra -std=c++17
LIB = -lcrypto
CC = g++

$(OUT): 
	$(CC) $(CFLAGS) $(SRC) $(LIB) -o $(OUT)

run: $(OUT)
	./${OUT}