CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDFLAGS ?=
LIBS = -lsqlite3 -lssl -lcrypto

all: file_cgi

file_cgi: main.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

# Unit tests
test_main: test_main.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

test: test_main
	./test_main

test-valgrind: test_main
	valgrind --leak-check=full --error-exitcode=1 ./test_main

clean:
	rm -f file_cgi main.o test_main test_main.o

.PHONY: all clean test test-valgrind
