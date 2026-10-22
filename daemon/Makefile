# Makefile for PoseaFilter pfSense / FreeBSD Daemon
CC ?= clang
CFLAGS ?= -O2 -Wall -Wextra -pthread -Iinclude -D_GNU_SOURCE
LDFLAGS ?= -pthread

TARGET = poseafilterd
SRCS = src/main.c \
       src/cJSON.c \
       src/dns_engine.c \
       src/filter_matcher.c \
       src/bsearch_feed.c \
       src/sni_parser.c \
       src/pf_manager.c \
       src/arp_bsd.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

install: $(TARGET)
	install -d /usr/local/sbin
	install -m 755 $(TARGET) /usr/local/sbin/$(TARGET)
	install -d /var/etc/poseafilter
	install -d /var/log/poseafilter

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean install
