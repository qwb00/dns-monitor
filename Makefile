TARGET = dns-monitor
CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap -lresolv
SRCS = src/main.c src/args.c src/dns_capture.c src/domains.c src/translations.c src/process_dns_packet.c src/print_dns.c
OBJS = $(SRCS:src/%.c=build/%.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

clean:
	rm -rf build $(TARGET)
