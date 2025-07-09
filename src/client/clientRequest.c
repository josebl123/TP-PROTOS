//
// Created by nicol on 7/7/2025.
//

#include "clientRequest.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "logger.h"
#include "util.h"
#include "selector.h"
#include "tcpClientUtil.h"
#include "clientAuth.h"
#include "args.h"
#include "logger.h"
#include "client.h"
#include <string.h>
#include <sys/socket.h>

unsigned handleRequestRead(struct selector_key *key) {
    clientData *data = key->data;
    int clntSocket = key->fd; // Socket del cliente

    log(INFO, "Reading request from client socket %d", clntSocket);

    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d: %s", clntSocket, strerror(errno));
        return ERROR_CLIENT; // TODO definir codigos de error
    }

    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }
    if(buffer_read(data->clientBuffer) != VERSION) {
        log(ERROR, "Invalid version in authentication request from client socket %d", clntSocket);
        return ERROR_CLIENT; // Abortamos si la versión no es correcta
    }
    if (buffer_read(data->clientBuffer) != RSV) {
        log(ERROR, "Invalid reserved byte in authentication request from client socket %d", clntSocket);
        return ERROR_CLIENT; // Abortamos si el byte reservado no es correcto
    }
    uint8_t option = buffer_read(data->clientBuffer); // Leer la longitud del username
    if(option == 0x01) {
        log(INFO, "User login, reading username");
        selector_set_interest_key(key, OP_WRITE); // Cambiamos a escritura
        return CONFIG_WRITE; // Abortamos si la longitud del username no es correcta
    }
    if( option == 0x00){
        log(INFO, "User login, reading stats");
        selector_set_interest_key(key, OP_READ); // Cambiamos a lectura
        return STATS_READ; // Si el cliente quiere leer stats, pasamos a ese estado

    }
    return ERROR_CLIENT; // Si no es un estado válido, abortamos
 }

unsigned handleRequestWrite(struct selector_key *key) {
    clientData *data = key->data;
    int clntSocket = key->fd; // Socket del cliente q

    int usernameLength = data->args->target_user ? strlen(data->args->target_user) : 0;

    int totalLength = 1 + 1 + 1 + usernameLength + 1; // Version + RSV + Option + Username + Null terminator

    log(INFO, "Writing request to client socket %d with username length %d", clntSocket, usernameLength);
    char *response = malloc(totalLength);
    if (response == NULL) {
        log(ERROR, "Memory allocation failed for response buffer");
        return ERROR_CLIENT; // Abortamos si no se pudo alocar memoria
    }
    response[0] = VERSION; // Version
    response[1] = RSV; // Reserved byte
    response[2] = data->args->stats ? 0x00 : 0x01; // Option: 0x00 for stats, 0x01 for config
    response[3] = usernameLength; // Length of username
    if (usernameLength > 0) {
        memcpy(response + 4, data->args->target_user, usernameLength); // Copiamos el username
    }
    ssize_t bytesSent = send(clntSocket, response, totalLength, 0);
    if (bytesSent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        free(response);
        return ERROR_CLIENT; // Abortamos si hubo error al enviar
    }
    if (bytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        free(response);
        return DONE; // Cliente cerró la conexión
    }
    log(INFO, "Sent %zd bytes to client socket %d", bytesSent, clntSocket);
    free(response); // Liberamos la memoria del response
    selector_set_interest_key(key, OP_READ); // Cambiamos a lectura
    return REQUEST_READ; // Pasamos al siguiente estado de lectura

  }