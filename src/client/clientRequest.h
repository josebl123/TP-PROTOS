//
// Created by nicol on 7/7/2025.
//

#ifndef CLIENTREQUEST_H
#define CLIENTREQUEST_H

#include "args.h"
#include "selector.h"

unsigned handleRequestRead(struct selector_key *key);
unsigned handleRequestWrite(struct selector_key *key);

#endif //CLIENTREQUEST_H
