# Vulnerable build — no compiler hardening flags.
# Bugs may be silent or produce undefined behaviour without a sanitiser.
# Compare with fixed/Makefile which adds -fsanitize=address,undefined.

CC     = gcc
CFLAGS = -g

.PHONY: all clean

all: memory_bugs heartbleed_sim

memory_bugs: memory_bugs.c
	$(CC) $(CFLAGS) -o memory_bugs memory_bugs.c

heartbleed_sim: heartbleed_sim.c
	$(CC) $(CFLAGS) -o heartbleed_sim heartbleed_sim.c

clean:
	rm -f memory_bugs heartbleed_sim
