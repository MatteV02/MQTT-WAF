CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -Iinclude
LDFLAGS = -shared
LDLIBS = -lmosquitto -lcyaml

TARGET = waf.so

SRCS = src/plugin.c src/message_logger.c src/message_forwarder.c src/settings.c src/subscription_logic.c src/waf_rules_parse.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean