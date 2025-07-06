//
// Created by nicol on 6/24/2025.
//

#ifndef SERVER_H
#define SERVER_H
#include <stdbool.h>
extern struct socks5args *socksArgs;
extern uint32_t bufferSize;
extern bool serverAcceptsNoAuth;

int setBufferSize(const char *sizeStr);
#endif //SERVER_H
