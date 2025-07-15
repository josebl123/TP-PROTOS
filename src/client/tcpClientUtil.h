//
// Created by nicol on 7/7/2025.
//

#ifndef TCPCLIENTUTILS_H
#define TCPCLIENTUTILS_H

#endif //TCPCLIENTUTILS_H
#include "client.h"
#include "../server/serverConfigTypes.h"


int tcp_client_socket(const char *host, const char *service);

unsigned handle_stats_read(client_data *data);
void handle_client_close(unsigned state, client_data *data);
