//
// Created by nicol on 6/26/2025.
//

#ifndef SOCKSAUTH_H
#define SOCKSAUTH_H
#include "tcpServerUtil.h"

#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64


// Handle reading the initial hello message from the client
unsigned handle_hello_read(struct selector_key *key);
// Handle writing the hello response to the client
unsigned handle_hello_write(struct selector_key *key);
// Handle reading the authentication message from the client
unsigned handle_auth_read(struct selector_key *key);
// Handle writing the authentication response to the client
unsigned handle_auth_write(struct selector_key *key);
#endif //SOCKSAUTH_H
