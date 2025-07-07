//
// Created by nicol on 7/7/2025.
//

#ifndef TCPCLIENTUTILS_H
#define TCPCLIENTUTILS_H

#endif //TCPCLIENTUTILS_H
#include "selector.h"
int tcpClientSocket(const char *host, const char *service);


void client_close(struct selector_key *key);
void client_read(struct selector_key *key);
void client_write(struct selector_key *key);
void client_block(struct selector_key *key);