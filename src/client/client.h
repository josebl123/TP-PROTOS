//
// Created by nicol on 6/24/2025.
//

#ifndef CLIENT_H
#define CLIENT_H
#include "args.h"
#include "stm.h"
#include "buffer.h"

#define VERSION 0x01 // Version for authentication subnegotiation
#define RSV 0x00 // Reserved byte for authentication subnegotiation
extern int clntSocket;
enum end_state {
    DONE,
    ERROR_CLIENT,
};
typedef struct clientData {
    struct state_machine *stm; // State machine for client
    buffer *clientBuffer; // Buffer for client data
    struct clientArgs * args; // Client arguments
} clientData;

#endif //CLIENT_H
