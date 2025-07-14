// clientRequest.c

#include "clientRequest.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "logger.h"
#include "selector.h"
#include "args.h"
#include "client.h"
#include "clientConfig.h"

#define VERSION_OFFSET         0
#define RSV_OFFSET             1
#define OPTION_OFFSET          2
#define USERNAME_LENGTH_OFFSET 3
#define HEADER_LENGTH          4 // VERSION + RSV + OPTION + USERNAME_LENGTH

#define OPTION_STATS  0x00
#define OPTION_CONFIG 0xFF

unsigned handleRequestRead(struct selector_key *key) {
    clientData *data = key->data;
    int clntSocket = key->fd;

    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d: %s", clntSocket, strerror(errno));
        return ERROR_CLIENT;
    }
    if (numBytesRcvd == 0) {
        return DONE;
    }
    if(buffer_read(data->clientBuffer) != VERSION) {
        log(ERROR, "Invalid version in authentication request from client socket %d", clntSocket);
        return ERROR_CLIENT;
    }
    if (buffer_read(data->clientBuffer) != RSV) {
        log(ERROR, "Invalid reserved byte in authentication request from client socket %d", clntSocket);
        return ERROR_CLIENT;
    }

    uint8_t status = buffer_read(data->clientBuffer);
    if(status == OPTION_CONFIG) {
        if (selector_set_interest_key(key, OP_WRITE)!= SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clntSocket);
            return ERROR_CLIENT;
        }
        return CONFIG_WRITE;
    }
    if(status == OPTION_STATS){
        if (selector_set_interest_key(key, OP_READ)!= SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clntSocket);
            return ERROR_CLIENT;
        }
        return STATS_READ;
    }
    if (status != OPTION_STATS && status != OPTION_CONFIG) {
        failure_response_print(status);
        return ERROR_CLIENT;
    }
    return ERROR_CLIENT;
}

unsigned handleRequestWrite(struct selector_key *key) {
    clientData *data = key->data;
    int clntSocket = key->fd;

    unsigned long usernameLength = data->args->target_user ? strlen(data->args->target_user) : 0;
    int totalLength = HEADER_LENGTH + usernameLength + 1; // +1 por el null terminator

    uint8_t *response = malloc(totalLength);
    if (response == NULL) {
        log(ERROR, "Memory allocation failed for response buffer");
        return ERROR_CLIENT;
    }
    response[VERSION_OFFSET]         = VERSION;
    response[RSV_OFFSET]             = RSV;
    response[OPTION_OFFSET]          = data->args->stats ? OPTION_STATS : OPTION_CONFIG;
    response[USERNAME_LENGTH_OFFSET] = usernameLength;
    if (usernameLength > 0) {
        memcpy(response + HEADER_LENGTH, data->args->target_user, usernameLength);
    }
    response[HEADER_LENGTH + usernameLength] = '\0'; // Null terminator

    ssize_t bytesSent = send(clntSocket, response, totalLength, 0);
    if (bytesSent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        free(response);
        return ERROR_CLIENT;
    }
    if (bytesSent == 0) {
        free(response);
        return DONE;
    }
    free(response);
    if (selector_set_interest_key(key, OP_READ)!= SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", clntSocket);
        return ERROR_CLIENT;
    }
    return REQUEST_READ;
}