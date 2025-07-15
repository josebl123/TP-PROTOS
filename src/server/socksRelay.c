//
// Created by nicol on 6/29/2025.
//

#include "socksRelay.h"
#include "tcpServerUtil.h"
#include "../utils/logger.h"
#include <errno.h>
#include <string.h>

#include "metrics/metrics.h"

int update_selector_interests(struct selector_key *key, client_data *client_data, int client_fd, int remote_fd) {
    fd_interest client_interest = OP_NOOP;
    fd_interest remote_interest = OP_NOOP;

    // === CLIENTE ===
    // ¿Podemos leer del cliente? (hay espacio en su buffer)
    if (buffer_can_write(client_data->client_buffer)) {
        client_interest |= OP_READ;
    }

    // ¿Podemos escribir al cliente? (hay datos del remoto para enviar)
    if (buffer_can_read(client_data->remote_buffer)) {
        client_interest |= OP_WRITE;
    }

    // === REMOTO ===
    // ¿Podemos leer del remoto? (hay espacio en su buffer)
    if (buffer_can_write(client_data->remote_buffer)) {
        remote_interest |= OP_READ;
    }

    // ¿Podemos escribir al remoto? (hay datos del cliente para enviar)
    if (buffer_can_read(client_data->client_buffer)) {
        remote_interest |= OP_WRITE;
    }

    // Aplicar los intereses
    if (selector_set_interest(key->s, client_fd, client_interest) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", client_fd);
        return -1;
    }
    if (selector_set_interest(key->s, remote_fd, remote_interest) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for remote socket %d", remote_fd);
        return -1;
    }
    return 0;
}


int handle_relay_remote_write_to_client_attempt(struct selector_key *key) {
    // Este estado se usa cuando se quiere escribir inmediatamente al remoto sin esperar a que haya datos del cliente
    client_data *data = key->data;
    int clnt_fd = data->client_socket; // Socket remoto

    // Enviar mensaje al remoto
    size_t read_limit;
    const uint8_t *read_ptr = buffer_read_ptr(data->remote_buffer, &read_limit);
    const ssize_t num_bytes_sent = send(clnt_fd, read_ptr, read_limit, 0);
    if (num_bytes_sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            if (update_selector_interests(key, data, clnt_fd, key->fd) < 0)
                return ERROR_CLIENT;
            return RELAY_REMOTE; // Mantener el estado de escritura de remoto relay
        }
        log(ERROR, "send() failed on remote socket %d", clnt_fd);
        metrics_add_send_error();
        return RELAY_ERROR;
    }
    if (num_bytes_sent == 0) {
        return RELAY_DONE;
    }
    buffer_read_adv(data->remote_buffer, num_bytes_sent); // Avanzar el puntero de lectura del buffer
    metrics_add_bytes_remote_to_client(num_bytes_sent);
    data->current_user_conn.bytes_received += num_bytes_sent;

    if (update_selector_interests(key, data, clnt_fd, key->fd) < 0)
        return ERROR_CLIENT;
    return RELAY_REMOTE; // Cambiar al estado de lectura de remoto relay
}

int handle_relay_client_write_to_remote_attempt(struct selector_key *key) {
    // Este estado se usa cuando se quiere escribir inmediatamente al cliente sin esperar a que haya datos del remoto
    client_data *data = key->data;
    const int remote_socket = data->remote_socket; // Socket del cliente

    // Enviar mensaje al cliente
    size_t read_limit;
    const uint8_t *read_ptr = buffer_read_ptr(data->client_buffer, &read_limit);
    const ssize_t num_bytes_sent = send(remote_socket, read_ptr, read_limit, 0);
    if (num_bytes_sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            if (update_selector_interests(key, key->data, key->fd, remote_socket)< 0)
                return ERROR_CLIENT;
            return RELAY_CLIENT; // Mantener el estado de escritura de cliente relay
        }
        log(ERROR, "send() failed on remote socket %d", remote_socket);
        metrics_add_send_error();
        return ERROR_CLIENT;
    }
    if (num_bytes_sent == 0) {
        return DONE;
    }
    buffer_read_adv(data->client_buffer, num_bytes_sent); // Avanzar el puntero de lectura del buffer
    metrics_add_bytes_client_to_remote(num_bytes_sent);
    data->current_user_conn.bytes_sent += num_bytes_sent;

    if (update_selector_interests(key, key->data, key->fd, remote_socket)< 0)
        return ERROR_CLIENT;
    return RELAY_CLIENT; // Cambiar al estado de lectura de cliente relay
}

int handle_relay_client_read_from_remote_attempt(struct selector_key *key) {
    // Este estado se usa cuando se quiere leer inmediatamente del remoto sin esperar a que haya datos del cliente
    client_data *data = key->data;
    const int remote_socket = data->remote_socket; // Socket del remoto

    // Recibir mensaje del remoto
    size_t write_limit;
    uint8_t *write_ptr = buffer_write_ptr(data->remote_buffer, &write_limit);
    const ssize_t num_bytes_rcvd = recv(remote_socket, write_ptr, write_limit, 0);
    if (num_bytes_rcvd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo recibir por ahora, volver a intentar más tarde
            if (update_selector_interests(key, key->data, key->fd, remote_socket)< 0)
                return ERROR_CLIENT;
            return RELAY_CLIENT; // Mantener el estado de lectura de cliente relay
        }
        if ( errno == ECONNRESET) {
            return RELAY_DONE; // El cliente cerró la conexión
        }
        log(ERROR, "recv() failed on remote socket %d: %s", remote_socket, strerror(errno));
        metrics_add_receive_error();
        return ERROR_CLIENT;
    }
    if (num_bytes_rcvd == 0) {
        return DONE;
    }
    buffer_write_adv(data->remote_buffer, num_bytes_rcvd); // Avanzar el puntero de escritura del buffer
    metrics_add_bytes_remote_to_client(num_bytes_rcvd);
    data->current_user_conn.bytes_received += num_bytes_rcvd;

    if (update_selector_interests(key, key->data, key->fd, remote_socket)< 0)
        return ERROR_CLIENT;
    return RELAY_CLIENT; // Cambiar al estado de lectura de cliente relay
}


int handle_relay_client_read_from_client_attempt(struct selector_key *key) {
    // Este estado se usa cuando se quiere leer inmediatamente del cliente sin esperar a que haya datos del remoto
    client_data *data = key->data;
    const int clnt_socket = data->client_socket; // Socket del cliente

    // Recibir mensaje del cliente
    size_t write_limit;
    uint8_t *write_ptr = buffer_write_ptr(data->remote_buffer, &write_limit);
    const ssize_t num_bytes_rcvd = recv(clnt_socket, write_ptr, write_limit, 0);
    if (num_bytes_rcvd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo recibir por ahora, volver a intentar más tarde
            if (update_selector_interests(key, data, clnt_socket, key->fd)< 0)
                return ERROR_CLIENT;
            return RELAY_REMOTE; // Mantener el estado de lectura de remoto relay
        }
        log(ERROR, "recv() failed on client socket %d: %s", clnt_socket, strerror(errno));
        if ( errno == ECONNRESET) {
            return RELAY_DONE; // El cliente cerró la conexión
        }
        metrics_add_receive_error();
        return RELAY_ERROR;
    }
    if (num_bytes_rcvd == 0) {
        return RELAY_DONE;
    }
    buffer_write_adv(data->remote_buffer, num_bytes_rcvd); // Avanzar el puntero de escritura del buffer
    metrics_add_bytes_client_to_remote(num_bytes_rcvd);
    data->current_user_conn.bytes_sent += num_bytes_rcvd;

    if (update_selector_interests(key, data, clnt_socket, key->fd)< 0)
        return ERROR_CLIENT;
    return RELAY_REMOTE; // Cambiar al estado de lectura de remoto relay
}


unsigned handle_relay_client_read(struct selector_key *key){
    const int clnt_socket = key->fd; // Socket del cliente
     client_data *data = key->data;

    // Recibir mensaje del cliente
    size_t write_limit;
    uint8_t *write_ptr = buffer_write_ptr(data->client_buffer, &write_limit);
    const ssize_t num_bytes_rcvd = recv(clnt_socket, write_ptr, write_limit, 0);
    if (num_bytes_rcvd < 0) {
        if ( errno == ECONNRESET) {
            return RELAY_DONE; // El cliente cerró la conexión
        }
        metrics_add_receive_error();
        return ERROR_CLIENT;
    }
    if (num_bytes_rcvd == 0) {
        return DONE;
    }
    buffer_write_adv(data->client_buffer, num_bytes_rcvd); // Avanzar el puntero de escritura del buffer
    metrics_add_bytes_client_to_remote(num_bytes_rcvd);
    data->current_user_conn.bytes_sent += num_bytes_rcvd;

    return handle_relay_client_write_to_remote_attempt(key); // Cambiar al estado de escritura de cliente relay
}

unsigned handle_relay_client_write(struct selector_key *key){
    int clnt_socket = key->fd; // Socket del cliente
    const client_data *data = key->data;

    // Enviar mensaje al cliente
    size_t read_limit;
    const uint8_t *read_ptr = buffer_read_ptr(data->remote_buffer, &read_limit);
    const ssize_t num_bytes_sent = send(clnt_socket, read_ptr, read_limit, 0);
    if (num_bytes_sent < 0) {
        log(ERROR, "send() failed on client socket %d", clnt_socket);
        metrics_add_send_error();
        return ERROR_CLIENT;
    }
    if (num_bytes_sent == 0) {
        return DONE;
    }
    buffer_read_adv(data->remote_buffer, num_bytes_sent); // Avanzar el puntero de lectura del buffer
    // metrics_add_bytes_remote_to_client(num_bytes_sent);
    client_data *client = key->data;
    client->current_user_conn.bytes_received += num_bytes_sent;

    return handle_relay_client_read_from_remote_attempt(key); // Cambiar al estado de lectura de cliente relay
  }
unsigned handle_relay_remote_read(struct selector_key *key) {
    const int remote_socket = key->fd; // Socket remoto
    client_data *data = key->data;
    // Recibir mensaje del socket remoto
    size_t write_limit;
    uint8_t *write_ptr = buffer_write_ptr(data->remote_buffer, &write_limit);
    const ssize_t num_bytes_rcvd = recv(remote_socket, write_ptr, write_limit, 0);
    if (num_bytes_rcvd < 0) {
        if ( errno == ECONNRESET) {
            return RELAY_DONE; // El cliente cerró la conexión
        }
        log(ERROR, "recv() failed on remote socket %d", remote_socket);

        metrics_add_receive_error();
        return RELAY_ERROR;
    }
    if (num_bytes_rcvd == 0) {
        return RELAY_DONE;
    }
    buffer_write_adv(data->remote_buffer, num_bytes_rcvd); // Avanzar el puntero de escritura del buffer
    metrics_add_bytes_remote_to_client(num_bytes_rcvd);
    data->current_user_conn.bytes_received += num_bytes_rcvd;

    return handle_relay_remote_write_to_client_attempt(key); // Cambiar al estado de escritura de remoto relay
}
unsigned handle_relay_remote_write(struct selector_key *key) {
    const int remote_socket = key->fd; // Socket remoto
    const client_data *data = key->data;
    // Enviar mensaje al socket remoto
    size_t read_limit;
    const uint8_t *read_ptr = buffer_read_ptr(data->client_buffer, &read_limit); //FIXME: data->client puede ser NULL si el cliente cierra la conexión antes de que se envíe el mensaje
    const ssize_t num_bytes_sent = send(remote_socket, read_ptr, read_limit, 0);
    if (num_bytes_sent < 0) {
        log(ERROR, "send() failed on remote socket %d", remote_socket);
        metrics_add_send_error();
        return RELAY_ERROR;
    }
    if (num_bytes_sent == 0) {
        return RELAY_DONE ;
    }
    buffer_read_adv(data->client_buffer, num_bytes_sent); // Avanzar el puntero de lectura del buffer
    // metrics_add_bytes_client_to_remote(num_bytes_sent);
    client_data *client = key->data;
    client->current_user_conn.bytes_sent += num_bytes_sent;

    return handle_relay_client_read_from_client_attempt(key); // Cambiar al estado de lectura de remoto relay
}



