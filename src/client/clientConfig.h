//
// Created by nicol on 7/7/2025.
//

#ifndef CLIENTCONFIG_H
#define CLIENTCONFIG_H
#include "selector.h"

unsigned handleConfigRead(struct selector_key *key);
unsigned handleConfigWrite(struct selector_key *key);
void failure_response_print(int response);

#endif //CLIENTCONFIG_H

