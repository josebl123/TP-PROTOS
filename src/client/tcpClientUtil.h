//
// Created by nicol on 7/7/2025.
//

#ifndef TCPCLIENTUTILS_H
#define TCPCLIENTUTILS_H

#endif //TCPCLIENTUTILS_H
#include "selector.h"

typedef enum {
    STATUS_OK = 0x00,
    STATUS_SERVER_GENERAL_FAILURE = 0x01,
    STATUS_BAD_REQUEST = 0x02,
} status_code;


int tcpClientSocket(const char *host, const char *service);

void client_close(struct selector_key *key);
void client_read(struct selector_key *key);
void client_write(struct selector_key *key);
void client_block(struct selector_key *key);
unsigned int handleStatsRead(struct selector_key *key);
void handleClientClose(unsigned state, struct selector_key *key);
