CC = gcc
LD = gcc
LIB= -pthread
#
SRCS = $(wildcard *.c)
#
OBJS = $(patsubst %c, %o, $(SRCS))
#
# # 可执行文件的名字
TARGET = mdm-server
#
.PHONY:all clean
#
# # 要生成的目标文件
all: $(TARGET)
#
$(TARGET): $(OBJS)
	$(LD) $(LIB) -o $@ $^
%o:%c
	$(CC)  -c $^
#
clean:
	rm -f $(OBJS) $(TARGET)
#
