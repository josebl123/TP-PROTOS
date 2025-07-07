//
// Created by nicol on 7/7/2025.
//

#ifndef CLIENTAUTH_H
#define CLIENTAUTH_H
#include "args.h"
#include "selector.h"

unsigned handleAuthRead(struct selector_key *key);
unsigned handleAuthWrite(struct selector_key *key);



#endif //CLIENTAUTH_H
