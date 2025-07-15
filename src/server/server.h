//
// Created by nicol on 6/24/2025.
//

#ifndef SERVER_H
#define SERVER_H
#include <stdbool.h>
#define MAX_CONNECTIONS 501 // Maximum number of concurrent connections
extern struct socks5args *socks_args;
extern uint32_t buffer_size;
extern int master_socket;
extern struct fd_selector *selector;

#endif //SERVER_H
