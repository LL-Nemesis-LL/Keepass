OUT = main

SRC = src/*.cpp main.cpp
CFLAGS = -O -Wall -Wextra -std=c++17
CC = g++
OBJ = $(SRC:.cpp = .o)

$(OUT): clean $(OBJ)
	$(CC) $(CFLAGS) -o $(OUT) $(OBJ)

clean:
	rm -f $(OUT) *.o 

run: $(OUT)
	./${OUT}