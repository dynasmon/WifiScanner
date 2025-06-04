CC=gcc
CFLAGS=-Wall -Wextra -pthread

SRC=$(wildcard src/*.c)
OBJ=$(SRC:.c=.o)

nico: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

clean:
	rm -f src/*.o nico
