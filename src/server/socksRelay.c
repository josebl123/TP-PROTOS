//
// Created by nicol on 6/29/2025.
//

#include "socksRelay.h"
#include "tcpServerUtil.h"
#include "../utils/logger.h"
#include <errno.h>
#include <string.h>

#include "metrics/metrics.h"

void update_selector_interests(struct selector_key *key, clientData *clientData, int clientFd, int remoteFd) {
    fd_interest client_interest = OP_NOOP;
    fd_interest remote_interest = OP_NOOP;

    // === CLIENTE ===
    // ¿Podemos leer del cliente? (hay espacio en su buffer)
    if (buffer_can_write(clientData->clientBuffer)) {
        client_interest |= OP_READ;
    }

    // ¿Podemos escribir al cliente? (hay datos del remoto para enviar)
    if (buffer_can_read(clientData->remoteBuffer)) {
        client_interest |= OP_WRITE;
    }

    // === REMOTO ===
    // ¿Podemos leer del remoto? (hay espacio en su buffer)
    if (buffer_can_write(clientData->remoteBuffer)) {
        remote_interest |= OP_READ;
    }

    // ¿Podemos escribir al remoto? (hay datos del cliente para enviar)
    if (buffer_can_read(clientData->clientBuffer)) {
        remote_interest |= OP_WRITE;
    }

    // Aplicar los intereses
    selector_set_interest(key->s, clientFd, client_interest);
    selector_set_interest(key->s, remoteFd, remote_interest);
}


int handleRelayRemoteWriteToClientAttempt(struct selector_key *key) {
    // Este estado se usa cuando se quiere escribir inmediatamente al remoto sin esperar a que haya datos del cliente
    remoteData *data = key->data;
    int clntFd = data->client_fd; // Socket remoto

    // Enviar mensaje al remoto
    size_t readLimit;
    const uint8_t *readPtr = buffer_read_ptr(data->client->remoteBuffer, &readLimit);
    const ssize_t numBytesSent = send(clntFd, readPtr, readLimit, MSG_DONTWAIT);
    if (numBytesSent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            update_selector_interests(key, data->client, clntFd, key->fd); // Actualizar los intereses del selector
            return RELAY_REMOTE; // Mantener el estado de escritura de remoto relay
        }
        log(ERROR, "send() failed on remote socket %d", clntFd);
        metrics_add_send_error();
        return RELAY_ERROR; // TODO definir codigos de error
    }
    if (numBytesSent == 0) {
        log(INFO, "Remote socket %d closed connection", clntFd);
        return RELAY_DONE; // TODO definir codigos de error
    }
    buffer_read_adv(data->client->remoteBuffer, numBytesSent); // Avanzar el puntero de lectura del buffer
    metrics_add_bytes_remote_to_client(numBytesSent);
    data->client->current_user_conn.bytes_received += numBytesSent;

    update_selector_interests(key, data->client, clntFd, key->fd); // Actualizar los intereses del selector

    return RELAY_REMOTE; // Cambiar al estado de lectura de remoto relay
}

int handleRelayClientWriteToRemoteAttempt(struct selector_key *key) {
    // Este estado se usa cuando se quiere escribir inmediatamente al cliente sin esperar a que haya datos del remoto
    clientData *data = key->data;
    int remoteSocket = data->remoteSocket; // Socket del cliente

    // Enviar mensaje al cliente
    size_t readLimit;
    const uint8_t *readPtr = buffer_read_ptr(data->clientBuffer, &readLimit);
    const ssize_t numBytesSent = send(remoteSocket, readPtr, readLimit, MSG_DONTWAIT);
    if (numBytesSent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            update_selector_interests(key, key->data, key->fd, remoteSocket); // Actualizar los intereses del selector
            return RELAY_CLIENT; // Mantener el estado de escritura de cliente relay
        }
        log(ERROR, "send() failed on remote socket %d", remoteSocket);
        metrics_add_send_error();
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesSent == 0) {
        log(INFO, "Remote socket %d closed connection", remoteSocket);
        return DONE; // TODO definir codigos de error
    }
    buffer_read_adv(data->clientBuffer, numBytesSent); // Avanzar el puntero de lectura del buffer
    metrics_add_bytes_client_to_remote(numBytesSent);
    data->current_user_conn.bytes_sent += numBytesSent;

    update_selector_interests(key, key->data, key->fd, remoteSocket); // Actualizar los intereses del selector

    return RELAY_CLIENT; // Cambiar al estado de lectura de cliente relay
}

int handleRelayClientReadFromRemoteAttempt(struct selector_key *key) {
    // Este estado se usa cuando se quiere leer inmediatamente del remoto sin esperar a que haya datos del cliente
    clientData *data = key->data;
    int remoteSocket = data->remoteSocket; // Socket del remoto

    // Recibir mensaje del remoto
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->remoteBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(remoteSocket, writePtr, writeLimit, 0);
    if (numBytesRcvd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo recibir por ahora, volver a intentar más tarde
            update_selector_interests(key, key->data, key->fd, remoteSocket); // Actualizar los intereses del selector
            return RELAY_CLIENT; // Mantener el estado de lectura de cliente relay
        }
        log(ERROR, "recv() failed on remote socket %d: %s", remoteSocket, strerror(errno));
        metrics_add_receive_error();
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Remote socket %d closed connection", remoteSocket);
        return DONE; // TODO definir codigos de error
    }
    buffer_write_adv(data->remoteBuffer, numBytesRcvd); // Avanzar el puntero de escritura del buffer
    metrics_add_bytes_remote_to_client(numBytesRcvd);
    data->current_user_conn.bytes_received += numBytesRcvd;

    update_selector_interests(key, key->data, key->fd, remoteSocket); // Actualizar los intereses del selector

    return RELAY_CLIENT; // Cambiar al estado de lectura de cliente relay
}


int handleRelayRemoteReadFromClientAttempt(struct selector_key *key) {
    // Este estado se usa cuando se quiere leer inmediatamente del cliente sin esperar a que haya datos del remoto
    remoteData *data = key->data;
    int clntSocket = data->client_fd; // Socket del cliente

    // Recibir mensaje del cliente
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->buffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    if (numBytesRcvd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo recibir por ahora, volver a intentar más tarde
            update_selector_interests(key, data->client, clntSocket, key->fd); // Actualizar los intereses del selector
            return RELAY_REMOTE; // Mantener el estado de lectura de remoto relay
        }
        log(ERROR, "recv() failed on client socket %d: %s", clntSocket, strerror(errno));
        metrics_add_receive_error();
        return RELAY_ERROR; // TODO definir codigos de error
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return RELAY_DONE; // TODO definir codigos de error
    }
    buffer_write_adv(data->buffer, numBytesRcvd); // Avanzar el puntero de escritura del buffer
    metrics_add_bytes_client_to_remote(numBytesRcvd);
    data->client->current_user_conn.bytes_sent += numBytesRcvd;

    update_selector_interests(key, data->client, clntSocket, key->fd); // Actualizar los intereses del selector

    return RELAY_REMOTE; // Cambiar al estado de lectura de remoto relay
}


unsigned handleRelayClientRead(struct selector_key *key){
    int clntSocket = key->fd; // Socket del cliente
     clientData *data = key->data;

    // Recibir mensaje del cliente
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d: %s", clntSocket, strerror(errno));
        metrics_add_receive_error();
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE; // TODO definir codigos de error
    }
    buffer_write_adv(data->clientBuffer, numBytesRcvd); // Avanzar el puntero de escritura del buffer
    metrics_add_bytes_client_to_remote(numBytesRcvd);
    data->current_user_conn.bytes_sent += numBytesRcvd;

//    update_selector_interests(key, key->data, clntSocket, data->remoteSocket); // Actualizar los intereses del selector

    return handleRelayClientWriteToRemoteAttempt(key); // Cambiar al estado de escritura de cliente relay
}

unsigned handleRelayClientWrite(struct selector_key *key){
    int clntSocket = key->fd; // Socket del cliente
    const clientData *data = key->data;

    // Enviar mensaje al cliente
    size_t readLimit;
    const uint8_t *readPtr = buffer_read_ptr(data->remoteBuffer, &readLimit);
    const ssize_t numBytesSent = send(clntSocket, readPtr, readLimit, MSG_DONTWAIT);
    if (numBytesSent < 0) {
        log(ERROR, "send() failed on client socket %d", clntSocket);
        metrics_add_send_error();
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE; // TODO definir codigos de error
    }
    buffer_read_adv(data->remoteBuffer, numBytesSent); // Avanzar el puntero de lectura del buffer
    // metrics_add_bytes_remote_to_client(numBytesSent);
    clientData *client = (clientData *)key->data;
    client->current_user_conn.bytes_received += numBytesSent;

//    update_selector_interests(key, key->data, clntSocket, data->remoteSocket); // Actualizar los intereses del selector

    return handleRelayClientReadFromRemoteAttempt(key); // Cambiar al estado de lectura de cliente relay
  }
unsigned handleRelayRemoteRead(struct selector_key *key) {
    const int remoteSocket = key->fd; // Socket remoto
    const remoteData *data = key->data;
    // Recibir mensaje del socket remoto
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->buffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(remoteSocket, writePtr, writeLimit, 0);
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on remote socket %d", remoteSocket);
        metrics_add_receive_error();
        return RELAY_ERROR; // TODO definir codigos de error
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Remote socket %d closed connection", remoteSocket);
        return RELAY_DONE; // TODO definir codigos de error
    }
    buffer_write_adv(data->buffer, numBytesRcvd); // Avanzar el puntero de escritura del buffer
    metrics_add_bytes_remote_to_client(numBytesRcvd);
    data->client->current_user_conn.bytes_received += numBytesRcvd;
    // Aquí se podría procesar el mensaje recibido del socket remoto
//    update_selector_interests(key, data->client, data->client_fd, remoteSocket); // Actualizar los intereses del selector

    return handleRelayRemoteWriteToClientAttempt(key); // Cambiar al estado de escritura de remoto relay
}
unsigned handleRelayRemoteWrite(struct selector_key *key) {
    const int remoteSocket = key->fd; // Socket remoto
    const remoteData *data = key->data;
    // Enviar mensaje al socket remoto
    size_t readLimit;
    const uint8_t *readPtr = buffer_read_ptr(data->client->clientBuffer, &readLimit); //FIXME: data->client puede ser NULL si el cliente cierra la conexión antes de que se envíe el mensaje
    const ssize_t numBytesSent = send(remoteSocket, readPtr, readLimit, MSG_DONTWAIT);
    if (numBytesSent < 0) {
        log(ERROR, "send() failed on remote socket %d", remoteSocket);
        metrics_add_send_error();
        return RELAY_ERROR; // TODO definir codigos de error
    }
    if (numBytesSent == 0) {
        log(INFO, "Remote socket %d closed connection", remoteSocket);
        return RELAY_DONE ; // TODO definir codigos de error
    }
    buffer_read_adv(data->client->clientBuffer, numBytesSent); // Avanzar el puntero de lectura del buffer
    // metrics_add_bytes_client_to_remote(numBytesSent);
    clientData *client = key->data;
    client->current_user_conn.bytes_sent += numBytesSent;


//    update_selector_interests(key, data->client, data->client_fd, remoteSocket);
    return handleRelayRemoteReadFromClientAttempt(key); // Cambiar al estado de lectura de remoto relay
}



