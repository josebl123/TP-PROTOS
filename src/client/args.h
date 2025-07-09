//
// Created by nicol on 7/7/2025.
//

#ifndef ARGS_H
#define ARGS_H
#include <stdio.h>
#include <stdbool.h>    /* for exit */
#include <stdint.h>    /* for uint32_t */
struct clientArgs {

    char* username;
    char* password;

    bool stats;
    bool user_stats;
    char* target_user;

    int verbose;

    char* addr;
    char* port;
    enum {
      BUFFER_SIZE, // Size of the buffer to use for reading/writing
      ACCEPTS_NO_AUTH, // If the client accepts no authentication
      ADD_USER,
       REMOVE_USER, // If the client removes a user
      MAKE_ADMIN, // If the client adds an admin
    } type;

    union {
      uint32_t buffer_size; // Address of the SOCKS server
        bool accepts_no_auth; // If the client accepts no authentication
        struct {
            char* name; // User to add
            char* pass; // Password for the user
        } user; // If the client adds a user
    };
};

void
parse_client_args(const int argc, char** argv, struct clientArgs* args);

#endif //ARGS_H
