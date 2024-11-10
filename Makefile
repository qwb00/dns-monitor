TARGET = dns-monitor
CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap -lresolv
SRCS = main.c args.c dns_capture.c domains.c translations.c process_dns_packet.c print_dns.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
