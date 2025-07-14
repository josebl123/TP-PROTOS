//
// Created by nicol on 7/7/2025.
//

#include "clientAuth.h"
#include "clientConfig.h"
#include "args.h"
#include "logger.h"
#include "client.h"
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include "clientConfig.h"

#include "server/serverConfigTypes.h"
#include "tcpClientUtil.h"
#include "clientRequest.h"

#define AUTH_VERSION_OFFSET      0
#define AUTH_RSV_OFFSET         1
#define AUTH_STATUS_OFFSET      2
#define AUTH_ROLE_OFFSET        3
#define AUTH_HEADER_LEN         4
#define AUTH_REQ_VERSION_OFFSET      0
#define AUTH_REQ_RSV_OFFSET         1
#define AUTH_REQ_USERLEN_OFFSET     2
#define AUTH_REQ_USERNAME_OFFSET    3

unsigned handleAuthRead(clientData *data) {

    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);

    if (numBytesRcvd <= 0) {
        if (numBytesRcvd == 0) {
                  return DONE;
        } else {
            log(ERROR, "recv() failed on client socket %d: %s", clntSocket, strerror(errno));
            return ERROR_CLIENT;
        }
    }

    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    size_t available;
    uint8_t *readPtr = buffer_read_ptr(data->clientBuffer, &available);
    if (available < AUTH_HEADER_LEN) return handleAuthRead(data);

    uint8_t version = readPtr[AUTH_VERSION_OFFSET];
    uint8_t rsv     = readPtr[AUTH_RSV_OFFSET];
    uint8_t status  = readPtr[AUTH_STATUS_OFFSET];
    uint8_t role    = readPtr[AUTH_ROLE_OFFSET];

    if (version != VERSION || rsv != RSV) {
        log(ERROR, "Invalid version or reserved byte");
        return ERROR_CLIENT;
    }


    buffer_read_adv(data->clientBuffer, AUTH_HEADER_LEN);


    if (status != STATUS_OK) {
        failure_response_print(status);
        return ERROR_CLIENT;
    }
    if (role == ROLE_USER) {
        if (data->args->flag == NULL || strcmp(data->args->flag, "default") != 0) {
            printf("### Unauthorized\n");
            return ERROR_CLIENT;
        }

        printf("## Authentication successful for user role\n");
        return handleStatsRead(data);
    }
    if (role == ROLE_ADMIN) {
        buffer_reset(data->clientBuffer);
        printf("## Authentication successful for Admin role\n");

        return handleRequestWrite(data);
    }

    log(ERROR, "Unknown role received: %02X", role);

    return ERROR_CLIENT;
}
unsigned handleAuthConfigSend(clientData *data, uint8_t *response, size_t responseSize) {

    ssize_t bytesSent = send(clntSocket, response, responseSize, 0);
    if (bytesSent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        free(response);
        return ERROR_CLIENT;
    }
    if (bytesSent == 0) {
        free(response);
        return DONE; // Connection closed
    }

    if ((size_t)bytesSent < responseSize) {
        return handleAuthConfigSend(data, response + bytesSent, responseSize - bytesSent); // Partial send, wait for next write
    }

    free(response);
    return handleAuthRead(data);
}

unsigned handleAuthWrite(clientData *data) {

    if (data->args->username == NULL || data->args->password == NULL) {
        log(ERROR, "Username or password not set");
        return ERROR_CLIENT;
    }

    uint8_t usernameLength = strlen(data->args->username);
    uint8_t passwordLength = strlen(data->args->password);

    int totalLength = AUTH_REQ_USERNAME_OFFSET + usernameLength + 1 + passwordLength;

    uint8_t *response = malloc(totalLength);
    if (response == NULL) {
        log(ERROR, "Memory allocation failed");
        return ERROR_CLIENT;
    }

    int offset = 0;
    response[offset++] = VERSION;
    response[offset++] = RSV;
    response[offset++] = usernameLength;
    memcpy(response + offset, data->args->username, usernameLength);
    offset += usernameLength;
    response[offset++] = passwordLength;
    memcpy(response + offset, data->args->password, passwordLength);

   return handleAuthConfigSend(data, response, totalLength);
}