//
// Created by nicol on 6/29/2025.
//

#include "socksRelay.h"
#include "tcpServerUtil.h"
#include "../utils/logger.h"
#include <errno.h>
#include <string.h>


unsigned handleRelayClientRead(struct selector_key *key){
    int clntSocket = key->fd; // Socket del cliente
    const clientData *data = key->data;

    // Recibir mensaje del cliente
    log(INFO, "Reading from client socket %d", clntSocket);
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d: %s", clntSocket, strerror(errno));
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE; // TODO definir codigos de error
    }
    buffer_write_adv(data->clientBuffer, numBytesRcvd); // Avanzar el puntero de escritura del buffer
    log(INFO, "Received %zd bytes from client socket %d", numBytesRcvd, clntSocket);
    log(INFO, "Message received from client: %.*s", (int)numBytesRcvd, (char *)writePtr);

    if (buffer_can_write(data->remoteBuffer)) {
        selector_set_interest(key->s, data->remoteSocket, OP_WRITE | OP_READ); // Cambiar el interés a escritura en el socket remoto
    } else {
        selector_set_interest(key->s, data->remoteSocket, OP_WRITE);
    }
    if ( buffer_can_write(data->clientBuffer) && buffer_can_read(data->remoteBuffer)  ) {
        selector_set_interest(key->s, clntSocket, OP_WRITE | OP_READ); // Cambiar el interés a escritura en el socket del cliente
    } else  if (buffer_can_write(data->clientBuffer)) {
        selector_set_interest(key->s, clntSocket, OP_READ);
    } else if (buffer_can_read(data->remoteBuffer)) {
        selector_set_interest(key->s, clntSocket, OP_WRITE); // Cambiar el interés a lectura en el socket del cliente
    } else {
        selector_set_interest(key->s, clntSocket, OP_NOOP); // Cambiar el interés a no hacer nada en el socket del cliente
    }

    // Aquí se podría procesar el mensaje recibido del cliente

    return RELAY_CLIENT; // Cambiar al estado de escritura de cliente relay
}

unsigned handleRelayClientWrite(struct selector_key *key){
    int clntSocket = key->fd; // Socket del cliente
    const clientData *data = key->data;

    // Enviar mensaje al cliente
    log(INFO, "Writing to client socket %d", clntSocket);
    size_t readLimit;
    const uint8_t *readPtr = buffer_read_ptr(data->remoteBuffer, &readLimit);
    const ssize_t numBytesSent = send(clntSocket, readPtr, readLimit, MSG_DONTWAIT);
    if (numBytesSent < 0) {
        log(ERROR, "send() failed on client socket %d", clntSocket);
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE; // TODO definir codigos de error
    }
    buffer_read_adv(data->remoteBuffer, numBytesSent); // Avanzar el puntero de lectura del buffer
    log(INFO, "Sent %zd bytes to client socket %d", numBytesSent, clntSocket);
    log(INFO, "Message sent to client: %.*s", (int)numBytesSent, (char *)readPtr);

    if (buffer_can_read(data->remoteBuffer) && buffer_can_write(data->clientBuffer)) {
        selector_set_interest(key->s, clntSocket, OP_READ | OP_WRITE); // Cambiar el interés a lectura y escritura en el socket del cliente
    } else if (buffer_can_read(data->remoteBuffer)) {
        selector_set_interest(key->s, clntSocket, OP_WRITE); // Cambiar el interés a lectura en el socket del cliente
    } else if (buffer_can_write(data->clientBuffer)) {
        selector_set_interest(key->s, clntSocket, OP_READ); // Cambiar el interés a escritura en el socket del cliente
    } else {
        selector_set_interest(key->s, clntSocket, OP_NOOP); // Cambiar el interés a no hacer nada en el socket del cliente
    }

    if (buffer_can_read(data->clientBuffer)) {
        selector_set_interest(key->s, data->remoteSocket, OP_READ | OP_WRITE); // Cambiar el interés a lectura en el socket remoto
    } else {
        selector_set_interest(key->s, data->remoteSocket, OP_READ); // Cambiar el interés a no hacer nada en el socket remoto
    }

    return RELAY_CLIENT; // Cambiar al estado de lectura de cliente relay
  }
unsigned handleRelayRemoteRead(struct selector_key *key) {
    const int remoteSocket = key->fd; // Socket remoto
    const remoteData *data = key->data;
    // Recibir mensaje del socket remoto
    log(INFO, "Reading from remote socket %d", remoteSocket);
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->buffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(remoteSocket, writePtr, writeLimit, 0);
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on remote socket %d", remoteSocket);
        return RELAY_ERROR; // TODO definir codigos de error
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Remote socket %d closed connection", remoteSocket);
        return RELAY_DONE; // TODO definir codigos de error
    }
    buffer_write_adv(data->buffer, numBytesRcvd); // Avanzar el puntero de escritura del buffer
    log(INFO, "Received %zd bytes from remote socket %d", numBytesRcvd, remoteSocket);
    log(INFO, "Message received from remote: %.*s", (int)numBytesRcvd, (char *)writePtr);
    // Aquí se podría procesar el mensaje recibido del socket remoto
    if (buffer_can_write(data->client->clientBuffer)) {
        selector_set_interest(key->s, data->client_fd, OP_WRITE | OP_READ); // Cambiar el interés a escritura en el socket remoto
    } else {
        selector_set_interest(key->s, data->client_fd, OP_WRITE);
    }
    if ( buffer_can_write(data->buffer) && buffer_can_read(data->client->clientBuffer)  ) {
        selector_set_interest(key->s, remoteSocket, OP_WRITE | OP_READ); // Cambiar el interés a escritura en el socket del cliente
    } else  if (buffer_can_write(data->client->clientBuffer)) {
        selector_set_interest(key->s, remoteSocket, OP_READ);
    } else if (buffer_can_read(data->buffer)) {
        selector_set_interest(key->s, remoteSocket, OP_WRITE); // Cambiar el interés a lectura en el socket del cliente
    } else {
        selector_set_interest(key->s, remoteSocket, OP_NOOP); // Cambiar el interés a no hacer nada en el socket del cliente
    }

    return  RELAY_REMOTE; // Cambiar al estado de escritura de remoto relay
}
unsigned handleRelayRemoteWrite(struct selector_key *key) {
    const int remoteSocket = key->fd; // Socket remoto
    const remoteData *data = key->data;
    // Enviar mensaje al socket remoto
    log(INFO, "Writing to remote socket %d", remoteSocket);
    size_t readLimit;
    const uint8_t *readPtr = buffer_read_ptr(data->client->clientBuffer, &readLimit);
    const ssize_t numBytesSent = send(remoteSocket, readPtr, readLimit, MSG_DONTWAIT);
    if (numBytesSent < 0) {
        log(ERROR, "send() failed on remote socket %d", remoteSocket);
        return RELAY_ERROR; // TODO definir codigos de error
    }
    if (numBytesSent == 0) {
        log(INFO, "Remote socket %d closed connection", remoteSocket);
        return RELAY_DONE ; // TODO definir codigos de error
    }
    buffer_read_adv(data->client->clientBuffer, numBytesSent); // Avanzar el puntero de lectura del buffer
    log(INFO, "Sent %zd bytes to remote socket %d", numBytesSent, remoteSocket);
    log(INFO, "Message sent to remote: %.*s", (int)numBytesSent, (char *)readPtr);

    if (buffer_can_read(data->client->clientBuffer) && buffer_can_write(data->buffer)) {
        selector_set_interest(key->s, remoteSocket, OP_READ | OP_WRITE); // Cambiar el interés a lectura y escritura en el socket del cliente
    } else if (buffer_can_read(data->client->clientBuffer)) {
        selector_set_interest(key->s, remoteSocket, OP_WRITE); // Cambiar el interés a lectura en el socket del cliente
    } else if (buffer_can_write(data->buffer)) {
        selector_set_interest(key->s, remoteSocket, OP_READ); // Cambiar el interés a escritura en el socket del cliente
    } else {
        selector_set_interest(key->s, remoteSocket, OP_NOOP); // Cambiar el interés a no hacer nada en el socket del cliente
    }

    if (buffer_can_read(data->buffer)) {
        selector_set_interest(key->s, data->client_fd, OP_READ | OP_WRITE); // Cambiar el interés a lectura en el socket remoto
    } else {
        selector_set_interest(key->s, data->client_fd, OP_READ); // Cambiar el interés a no hacer nada en el socket remoto
    }
    return RELAY_REMOTE; // Cambiar al estado de lectura de remoto relay
}
