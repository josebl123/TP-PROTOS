// clientRequest.c

#include "clientRequest.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "logger.h"
#include "args.h"
#include "client.h"
#include "clientConfig.h"

#define VERSION_OFFSET         0
#define RSV_OFFSET             1
#define OPTION_OFFSET          2
#define USERNAME_LENGTH_OFFSET 3
#define HEADER_LENGTH          4 // VERSION + RSV + OPTION + USERNAME_LENGTH
#define RESPONSE_HEADER_LENGTH 3 // VERSION + RSV + OPTION

#define OPTION_STATS  0x00
#define OPTION_CONFIG 0xFF
#include "tcpClientUtil.h"

unsigned handleRequestRead(clientData *data) {

    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);


    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d: %s", clntSocket, strerror(errno));
        return ERROR_CLIENT;
    }
    if (numBytesRcvd == 0) {
        return DONE;
    }
    buffer_write_adv(data->clientBuffer, numBytesRcvd);
    size_t available;
    buffer_read_ptr(data->clientBuffer, &available);
    if (available < RESPONSE_HEADER_LENGTH) {
        return handleRequestRead(data); // Not enough data yet
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
        return handleConfigWrite(data);
    }
    if(status == OPTION_STATS){
        return handleStatsRead(data);
    }
    if (status != OPTION_STATS && status != OPTION_CONFIG) {
        failure_response_print(status);
        return ERROR_CLIENT;
    }
    return ERROR_CLIENT;
}

unsigned handleRequestSend(clientData * data) {
    size_t availableBytes;
    uint8_t *readPtr = buffer_read_ptr(data->clientBuffer, &availableBytes);
    ssize_t bytesSent = send(clntSocket, readPtr, availableBytes, 0);
    if (bytesSent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        return ERROR_CLIENT;
    }
    if (bytesSent == 0) {
        return DONE;

    }
    buffer_read_adv(data->clientBuffer, bytesSent); // Avanzar el puntero de lectura del buffer
    if((size_t)bytesSent < availableBytes) {
      log(INFO, "Partial send, waiting for next write");
        return handleRequestSend(data);
    }
    return handleRequestRead(data);
}
unsigned handleRequestWrite(clientData *data) {


    unsigned long usernameLength = data->args->target_user ? strlen(data->args->target_user) : 0;
    int totalLength = HEADER_LENGTH + usernameLength + 1; // +1 por el null terminator

    buffer_reset(data->clientBuffer);
    size_t availableBytes;
    uint8_t * writePtr = buffer_write_ptr(data->clientBuffer, &availableBytes);
    if( availableBytes < (size_t)totalLength ){
        log(ERROR, "Not enough space in buffer to write request: %d bytes needed, %zu available", totalLength, availableBytes);
        return ERROR_CLIENT;
    }

    writePtr[VERSION_OFFSET]         = VERSION;
    writePtr[RSV_OFFSET]             = RSV;
    writePtr[OPTION_OFFSET]          = data->args->stats ? OPTION_STATS : OPTION_CONFIG;
    writePtr[USERNAME_LENGTH_OFFSET] = usernameLength;



    if (usernameLength > 0) {
        memcpy(writePtr + HEADER_LENGTH, data->args->target_user, usernameLength);
    }
    writePtr[HEADER_LENGTH + usernameLength] = '\0'; // Null terminator
    buffer_write_adv(data->clientBuffer, totalLength);
    return handleRequestSend(data);
}