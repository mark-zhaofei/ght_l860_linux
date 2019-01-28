#
# Copyright (C) 2018 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

FLAGS = -c -g -Wall
SOURCES = \
	../safeclib/strstr_s.c \
	../safeclib/safe_mem_constraint.c \
	../safeclib/mem_primitives_lib.c \
	../safeclib/safe_str_constraint.c \
	../safeclib/ignore_handler_s.c \
	../safeclib/strcmp_s.c \
	../safeclib/strncpy_s.c \
	../safeclib/memcpy_s.c \
	../safeclib/strnlen_s.c

OBJS = *.o

sock_app:sock_app.o
	gcc -o sock_app $(OBJS) -lpthread

sock_app.o:
	gcc ${FLAGS} sock_app.c $(SOURCES)

clean:
	rm -f *~ *.o sock_app xxx
