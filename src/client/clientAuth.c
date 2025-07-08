//
// Created by nicol on 7/7/2025.
//

#include "clientAuth.h"
#include "args.h"
#include "logger.h"
#include "client.h"
#include <string.h>
#include <sys/socket.h>
#include <errno.h>


unsigned handleAuthRead(struct selector_key *key){
    const int clntSocket = key->fd;
    struct clientData *data = key->data;

    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);

    if (numBytesRcvd <= 0) {
        if (numBytesRcvd == 0) {
            log(INFO, "Client socket %d closed connection", clntSocket);
        }
        else {
            log(ERROR, "recv() failed on client socket %d: %s", clntSocket, strerror(errno));
        }
        return DONE;
    }

    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    size_t available;
    uint8_t *readPtr = buffer_read_ptr(data->clientBuffer, &available);
    if (available < 4) return AUTH_READ;

    uint8_t version = readPtr[0];
    uint8_t rsv     = readPtr[1];
    uint8_t status  = readPtr[2];
    uint8_t role    = readPtr[3];

    if (version != VERSION || rsv != RSV) {
        log(ERROR, "Invalid version or reserved byte");
        return ERROR_CLIENT;
    }

    buffer_read_adv(data->clientBuffer, 4);

    if (status != 0x00) {
        log(ERROR, "Authentication failed: STATUS = %02X", status);
        return ERROR_CLIENT;
    }

    if (role == 0x00) {
        log(INFO, "Authenticated as USER");
        selector_set_interest_key(key, OP_READ);
        return STATS_READ;
    }
    if (role == 0x01) {
        log(INFO, "Authenticated as ADMIN");
        buffer_reset(data->clientBuffer); // Limpiar el buffer del cliente
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_WRITE;
    }

        log(ERROR, "Unknown role received: %02X", role);
        return ERROR_CLIENT;
}

unsigned handleAuthWrite(struct selector_key *key){
    const int clntSocket = key->fd; // Socket del cliente
    struct clientData *data = key->data; // Datos del cliente
    log(INFO, "Writing authentication request to client socket %d", clntSocket);

    if (data->args->username == NULL || data->args->password == NULL) {
        log(ERROR, "Username or password not set");
        return ERROR_CLIENT; // Abortamos si no hay usuario o contraseña
    }

    uint8_t usernameLength = strlen(data->args->username);
    uint8_t passwordLength = strlen(data->args->password);

    // Longitud total de la respuesta
    int totalLength = 1 + 1 + 1 + usernameLength + 1 + passwordLength;

    // Reservamos espacio dinámicamente o en stack si sabés que no será muy grande
    char *response = malloc(totalLength);
    if (response == NULL) {
        log(ERROR, "Memory allocation failed");
        return ERROR_CLIENT;
    }

    // Armamos el mensaje
    int offset = 0;
    response[offset++] = VERSION;                  // Versión del protocolo
    response[offset++] = RSV;                      // Reserved, típicamente 0x00
    response[offset++] = (uint8_t)usernameLength;  // Longitud del username
    memcpy(response + offset, data->args->username, usernameLength); // USERNAME
    offset += usernameLength;
    response[offset++] = (uint8_t)passwordLength;  // Longitud del password
    memcpy(response + offset, data->args->password, passwordLength); // PASSWORD

    log(INFO, "Prepared authentication request for client socket %d: %s:%s",
        clntSocket, data->args->username, data->args->password);

    log(INFO, "User and pass to be sent: %s %s %d", response + 3, response + 8, *(response + 7) ); // Imprimir desde el offset 3 para omitir versión y RSV


    // Enviar al cliente (ejemplo: write o send)
    ssize_t sent = send(clntSocket, response, totalLength, 0);
    if( sent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        free(response);
        return ERROR_CLIENT; // Abortamos si hubo error al enviar
    }
    if (sent == 0) {
        log(INFO, "Closed");
        free(response);
        return DONE;
    }
    log(INFO, "Sent authentication request to client socket %d", clntSocket);

    free(response);
    selector_set_interest_key(key, OP_READ);
    return AUTH_READ; // Cambiar al estado de lectura de autenticación
 }