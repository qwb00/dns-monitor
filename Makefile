TARGET = dns-monitor
CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap
SRCS = main.c args.c dns_capture.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
