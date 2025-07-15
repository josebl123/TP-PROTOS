CC = gcc
CFLAGS = -Wall -Wextra -g -Isrc/utils -D_GNU_SOURCE
BIN = server
CLIENT_BIN = client
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
       $(SRC_DIR)/utils/rbt.c \
       $(SRC_DIR)/stm.c \
       $(SRC_DIR)/buffer.c \
       $(SRC_DIR)/server/socksRelay.c \
       $(SRC_DIR)/metrics/metrics.c \
       $(SRC_DIR)/server/tcpServerConfigUtil.c \
       $(SRC_DIR)/utils/user_metrics_table.c \
       $(SRC_DIR)/utils/args.c \
       $(SRC_DIR)/server/socksRequest.c \
       $(SRC_DIR)/server/serverConfigActions.c \

# Source files for the client
CLIENT_SRCS = $(SRC_DIR)/client/client.c \
              $(SRC_DIR)/utils/util.c \
              $(SRC_DIR)/utils/logger.c \
              $(SRC_DIR)/client/args.c \
              $(SRC_DIR)/client/tcpClientUtil.c \
              $(SRC_DIR)/buffer.c \
              $(SRC_DIR)/stm.c \
              $(SRC_DIR)/selector.c \
              $(SRC_DIR)/utils/netutils.c \
              $(SRC_DIR)/client/clientAuth.c \
              $(SRC_DIR)/client/clientRequest.c \
              $(SRC_DIR)/client/clientConfig.c \


# Object files
SERVER_OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SERVER_SRCS))
CLIENT_OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(CLIENT_SRCS))

# Include directories
INCLUDES = -I$(SRC_DIR)

# Check unit testing framework flags
CHECK_FLAGS = $(shell pkg-config --cflags --libs check)

# Ensure the directories exist
DIRS = $(OBJ_DIR) $(BIN_DIR) $(OBJ_DIR)/utils $(OBJ_DIR)/server $(OBJ_DIR)/client $(OBJ_DIR)/metrics
.PHONY: all clean test client runclient

all: dirs $(BIN_DIR)/$(BIN) $(BIN_DIR)/$(CLIENT_BIN)

client: dirs $(BIN_DIR)/$(CLIENT_BIN)

server: dirs $(BIN_DIR)/$(BIN)

dirs:
	mkdir -p $(DIRS)

# Main server target
$(BIN_DIR)/$(BIN): $(SERVER_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ -lpthread -lanl

# Client target
$(BIN_DIR)/$(CLIENT_BIN): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ -lpthread

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# Clean up
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Run the server
run: all
	./$(BIN_DIR)/$(BIN)

# Run the client
runclient: client
	./$(BIN_DIR)/$(CLIENT_BIN)

valgrind: $(BIN_DIR)/$(BIN)
	valgrind --leak-check=full --show-leak-kinds=all ./$(BIN_DIR)/$(BIN)

valgrindclient: $(BIN_DIR)/$(CLIENT_BIN)
	valgrind --leak-check=full --show-leak-kinds=all ./$(BIN_DIR)/$(CLIENT_BIN)
