# Makefile of sm3sum

CC ?= gcc
# CFLAGS += -Wall -Wextra -Werror -g -O2 # -DDEBUG
CFLAGS += -Wall -Werror -g -O2 # -DDEBUG
# CFLAGS += -Wall -Werror -g -DDEBUG

HEADERS = sm3.h unit_test.h
OBJECTS = sm3sum.o sm3.o unit_test.o file_handler.o

default: sm3sum

%.o: %.c $(HEADERS)
	${CC} -c $< ${CFLAGS} -o $@

sm3sum: $(OBJECTS)
	${CC} ${OBJECTS} ${CFLAGS} -o $@

clean:
	rm *.o
	rm sm3sum
