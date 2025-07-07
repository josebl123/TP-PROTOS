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
    const int clntSocket = key->fd; // Socket del cliente
    struct clientData *data = key->data; // Datos del cliente

    // Leer datos de autenticación del cliente
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d: %s", clntSocket, strerror(errno));
        return ERROR_CLIENT; // Abortamos si hubo error al recibir
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE; // Cliente cerró la conexión
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
    if(option == 0x01) { // Solo soportamos un username
        return REQUEST_WRITE; // Abortamos si la longitud del username no es correcta
    }
    if( option == 0x00){
      log(INFO, "User login, reading stats");
        return STATS_READ; // Si el cliente quiere leer stats, pasamos a ese estado

     }
     return ERROR_CLIENT; // Si no es un estado válido, abortamos

  }
unsigned handleAuthWrite(struct selector_key *key){
    const int clntSocket = key->fd; // Socket del cliente
    struct clientData *data = key->data; // Datos del cliente

    if (data->args->username == NULL || data->args->password == NULL) {
        log(ERROR, "Username or password not set");
        return ERROR_CLIENT; // Abortamos si no hay usuario o contraseña
    }

    int usernameLength = strlen(data->args->username);
    int passwordLength = strlen(data->args->password);

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

    free(response);
    return AUTH_READ; // Cambiar al estado de lectura de autenticación


 }