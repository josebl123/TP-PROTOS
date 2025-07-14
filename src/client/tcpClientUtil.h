//
// Created by nicol on 7/7/2025.
//

#ifndef TCPCLIENTUTILS_H
#define TCPCLIENTUTILS_H

#endif //TCPCLIENTUTILS_H
#include "client.h"
#include "../server/serverConfigTypes.h"


int tcpClientSocket(const char *host, const char *service);

unsigned handleStatsRead(clientData *data);
void handleClientClose(unsigned state, clientData *data);
