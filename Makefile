# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -Iinclude -I/opt/oracle/sdk/include
LDFLAGS = -lcrypto -lz -lssl -lclntsh -locilib -lodpic

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
INCLUDE_DIR = include

# Ensure necessary directories exist
$(shell mkdir -p $(OBJ_DIR) $(BIN_DIR))

# Source files
SRCS_SERVER = main.c poll.c crypt.c msg.c zip.c cmd.c conn.c common.c net.c db.c
SRCS_CLIENT = client.c poll.c crypt.c msg.c zip.c conn.c cmd.c common.c net.c db.c

# Object files
OBJS_SERVER = $(patsubst %.c, $(OBJ_DIR)/%.o, $(SRCS_SERVER))
OBJS_CLIENT = $(patsubst %.c, $(OBJ_DIR)/%.o, $(SRCS_CLIENT))

# Output binaries
SERVER_BIN = $(BIN_DIR)/server
CLIENT_BIN = $(BIN_DIR)/client

# Default target
all: $(SERVER_BIN) $(CLIENT_BIN)

# Build the server program
$(SERVER_BIN): $(OBJS_SERVER)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Build the client program
$(CLIENT_BIN): $(OBJS_CLIENT)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Generic rule to compile source files into object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Print help
help:
	@echo "Targets:"
	@echo "  all       - Build both server and client programs"
	@echo "  clean     - Remove all generated files"
	@echo "  $(SERVER_BIN) - Build the server program"
	@echo "  $(CLIENT_BIN) - Build the client program"

