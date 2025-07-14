//
// Created by nicol on 7/7/2025.
//

#ifndef CLIENTCONFIG_H
#define CLIENTCONFIG_H
#include "client.h"

unsigned handleConfigRead(clientData * data);
unsigned handleConfigWrite(clientData * data);
void failure_response_print(int response);

#endif //CLIENTCONFIG_H

