CC = gcc
CFLAGS = -Wall -Wextra -g -Isrc/utils
BIN = server
TEST_BIN = test_program
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Source files for the main server
SERVER_SRCS = $(SRC_DIR)/server/server.c \
       $(SRC_DIR)/selector.c \
       $(SRC_DIR)/server/tcpServerUtil.c \
       $(SRC_DIR)/server/socksAuth.c \
       $(SRC_DIR)/utils/util.c \
       $(SRC_DIR)/utils/logger.c \
       $(SRC_DIR)/stm.c \
       $(SRC_DIR)/buffer.c \
       $(SRC_DIR)/server/socksRelay.c \
       $(SRC_DIR)/metrics/metrics.c \


# Source files for the tests
TEST_SRCS = $(SRC_DIR)/test/buffer_test.c \
       $(SRC_DIR)/buffer.c \
       $(SRC_DIR)/test/netutils_test.c \
       $(SRC_DIR)/utils/netutils.c \
       $(SRC_DIR)/test/parser_test.c \
       $(SRC_DIR)/parser.c \
       $(SRC_DIR)/test/parser_utils_test.c \
       $(SRC_DIR)/parser_utils.c \
       $(SRC_DIR)/test/selector_test.c \
       $(SRC_DIR)/selector.c \
       $(SRC_DIR)/test/stm_test.c \
       $(SRC_DIR)/stm.c

# Object files
SERVER_OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SERVER_SRCS))
TEST_OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(TEST_SRCS))

# Include directories
INCLUDES = -I$(SRC_DIR)

# Check unit testing framework flags
CHECK_FLAGS = $(shell pkg-config --cflags --libs check)

# Ensure the directories exist
DIRS = $(OBJ_DIR) $(BIN_DIR) $(OBJ_DIR)/utils $(OBJ_DIR)/server $(OBJ_DIR)/test $(OBJ_DIR)/metrics
.PHONY: all clean test

all: dirs $(BIN_DIR)/$(BIN)

test: dirs $(BIN_DIR)/$(TEST_BIN)

dirs:
	mkdir -p $(DIRS)

# Main server target
$(BIN_DIR)/$(BIN): $(SERVER_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ -lpthread

# Test target
$(BIN_DIR)/$(TEST_BIN): $(TEST_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ -lpthread $(CHECK_FLAGS)

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# Clean up
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Run the server
run: all
	./$(BIN_DIR)/$(BIN)

# Run the tests
runtest: test
	./$(BIN_DIR)/$(TEST_BIN)
