//
// Created by nicol on 6/24/2025.
//

#ifndef SERVER_H
#define SERVER_H
#include <stdbool.h>
#define MAX_CONNECTIONS 500 // Maximum number of concurrent connections
extern struct socks5args *socksArgs;
extern uint32_t bufferSize;
extern int master_socket;
extern struct fdselector *selector;

int setBufferSize(const char *sizeStr);
#endif //SERVER_H
