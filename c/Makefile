# Build libfalconseedgen.so using multiple PQClean Falcon schemes + fips202.

PQCLEAN_DIR := ../PQClean

FALCON512_DIR        := $(PQCLEAN_DIR)/falcon/falcon-512
FALCON512PADDED_DIR  := $(PQCLEAN_DIR)/falcon/falcon-padded-512
FALCON1024_DIR       := $(PQCLEAN_DIR)/falcon/falcon-1024
FALCON1024PADDED_DIR := $(PQCLEAN_DIR)/falcon/falcon-padded-1024

COMMON_DIR := $(PQCLEAN_DIR)/common

LIB_NAME := libfalconseedgen.so

CC := gcc
CFLAGS := -O3 -fPIC -Wall -Wextra \
          -I$(FALCON512_DIR) -I$(FALCON512PADDED_DIR) \
          -I$(FALCON1024_DIR) -I$(FALCON1024PADDED_DIR) \
          -I$(COMMON_DIR)

LDFLAGS := -shared

# Collect all scheme sources
FALCON_SOURCES := \
  $(wildcard $(FALCON512_DIR)/*.c) \
  $(wildcard $(FALCON512PADDED_DIR)/*.c) \
  $(wildcard $(FALCON1024_DIR)/*.c) \
  $(wildcard $(FALCON1024PADDED_DIR)/*.c)

# Remove any randombytes.c (we provide our own DRBG)
FALCON_SOURCES := $(filter-out %/randombytes.c,$(FALCON_SOURCES))

# SHAKE256 source
SHA3_SOURCES := $(COMMON_DIR)/fips202.c

# Our wrapper
WRAPPER_SOURCES := falcon_seedgen.c

SOURCES := $(FALCON_SOURCES) $(SHA3_SOURCES) $(WRAPPER_SOURCES)
OBJECTS := $(SOURCES:.c=.o)

all: $(LIB_NAME)

$(LIB_NAME): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(LIB_NAME)
