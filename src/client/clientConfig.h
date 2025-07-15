//
// Created by nicol on 7/7/2025.
//

#ifndef CLIENTCONFIG_H
#define CLIENTCONFIG_H
#include "client.h"

unsigned handle_config_read(client_data * data);
unsigned handle_config_write(client_data * data);
void failure_response_print(int response);

#endif //CLIENTCONFIG_H

