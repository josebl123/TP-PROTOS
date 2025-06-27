//
// Created by nicol on 6/26/2025.
//

#ifndef SOCKSAUTH_H
#define SOCKSAUTH_H
#include "tcpServerUtil.h"


// Handle reading the initial hello message from the client
unsigned handleHelloRead(struct selector_key *key);
// Handle writing the hello response to the client
unsigned handleHelloWrite(struct selector_key *key);
// Handle reading the authentication message from the client
unsigned handleAuthRead(struct selector_key *key);
// Handle writing the authentication response to the client
unsigned handleAuthWrite(struct selector_key *key);
#endif //SOCKSAUTH_H
