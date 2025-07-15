//
// Created by nicol on 7/5/2025.
//

#include "socksRequest.h"
#include "tcpServerUtil.h"
#include "utils/util.h"
#include "logger.h"
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include  <signal.h>
#define SOCKS5_REQUEST_HEADER_SIZE 4 // Size of the SOCKS5 request header (version, command, reserved, address type)
static char addr_buffer[MAX_ADDR_BUFFER];

unsigned connect_write(struct selector_key * key) {
    client_data *data = key->data;

    int error =0;
    socklen_t len = sizeof(error);
    clock_gettime(CLOCK_MONOTONIC, & data->last_activity);
    if ( getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        log(ERROR, "getsockopt() failed: %s", strerror(errno));
        data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return send_failure_response_remote(key); // Change to the relay error state
    }

    if (error != 0) {
        set_response_status(data, error);
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for remote socket %d", key->fd);
            return send_failure_response_remote(key);
        }
        if (data->destination.address_type == DOMAINNAME) {
            if (selector_notify_block(key->s, data->client_socket, NULL) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to notify selector for client socket %d", key->fd);
                return send_failure_response_remote(key);
            }
            data->address_resolved = 0; // Indicate that the callback is not ready
            return RELAY_CONNECTING; // Stay in the connecting state to retry the connection
        }

        return send_failure_response_remote(key); // Change to the relay error state
    }

    data->response_status = SOCKS5_SUCCEEDED; // Set response status to success
    data->address_resolved = 1;
    if (data->destination.address_type == DOMAINNAME) {
        if (selector_notify_block(key->s,data->client_socket, NULL) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to notify selector for client socket %d", key->fd);
            data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
            return send_failure_response_remote(key);
        }
    } else {
        if (selector_set_interest(key->s, data->client_socket, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
            return send_failure_response_remote(key);
        }
    }
    if (selector_set_interest(key->s, key->fd, OP_NOOP) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for remote socket %d", key->fd);
        data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return send_failure_response_remote(key);
    }
    return RELAY_REMOTE; // Change to the relay remote state
}

unsigned send_failure_response(client_data *data, int clnt_socket, unsigned error, unsigned done, struct selector_key *key) {

    char response[SOCKS5_MAX_REQUEST_RESPONSE] = {0}; // Buffer for the response
    response[0] = SOCKS_VERSION; // Versión del protocolo SOCKS
    response[1] = data->response_status; // Respuesta de error
    response[2] = RSV; // Reservado, debe ser 0x00
    response[3] = IPV4; // Address type (0 for IPv4)

    const ssize_t num_bytes_sent = send(clnt_socket, response, SOCKS5_IPV4_REQUEST, 0); // Send the failure response
    if (num_bytes_sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
                return error;
            }
            return FAILURE_RESPONSE; // Return to retry later
        }
        if (errno == ECONNRESET || errno == ECONNREFUSED || errno == EPIPE) {
            log(INFO, "Client socket %d closed connection: %s", clnt_socket, strerror(errno));
            return DONE; // Client closed the connection
        }
        log(ERROR, "send() failed on client socket %d: %s", clnt_socket, strerror(errno));
    }
    return error;
}

unsigned send_failure_response_client(struct selector_key *key) {
    return send_failure_response(key->data, key->fd, ERROR_CLIENT, DONE, key);
}

unsigned send_failure_response_remote(struct selector_key *key) {
    client_data *data = key->data;
    return send_failure_response(data, data->client_socket, RELAY_ERROR, RELAY_DONE, key);
}

unsigned handle_request_write(struct selector_key *key) {
    int clnt_socket = key->fd; // Socket del cliente
    client_data *data = key->data;

    if (data->response_status != SOCKS5_SUCCEEDED) {
        log(ERROR, "Connection failed with status: %d", data->response_status);
        return send_failure_response_client(key); // Send failure response to client
    }

    // Get the local address info for the remote socket
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len = sizeof(local_addr);
    if (getsockname(data->remote_socket, (struct sockaddr *)&local_addr, &local_addr_len) < 0) {
        log(ERROR, "Failed to get local socket address: %s", strerror(errno));
        data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return send_failure_response_client(key); // Send failure response to client
    }

    char response[SOCKS5_MAX_REQUEST_RESPONSE] = {0}; // Buffer para la respuesta

    // Prepare the response to send to the client
    response[0] = SOCKS_VERSION; // Versión del protocolo SOCKS
    response[1] = data->response_status; // Respuesta OK (no error)
    response[2] = RSV; // Reservado, debe ser 0x00

    // Fill the response with the bound address and port that the client should use
    if (local_addr.ss_family == AF_INET) {
        // IPv4 address
        const struct sockaddr_in *addr = (struct sockaddr_in *)&local_addr;
        response[3] = IPV4; // Address type is IPv4
        memcpy(response + REQUEST_HEADER, &addr->sin_addr, sizeof(addr->sin_addr)); // Copy the bound IPv4 address
        memcpy(response + REQUEST_HEADER + IPV4_ADDR_SIZE, &addr->sin_port, sizeof(addr->sin_port)); // Copy the bound port (already in network byte order)

        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr->sin_addr), addr_str, sizeof(addr_str));
    } else if (local_addr.ss_family == AF_INET6) {
        // IPv6 address
        const struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&local_addr;
        response[3] = IPV6; // Address type is IPv6
        memcpy(response + REQUEST_HEADER, &addr->sin6_addr, sizeof(addr->sin6_addr)); // Copy the bound IPv6 address
        memcpy(response + REQUEST_HEADER + IPV6_ADDR_SIZE, &addr->sin6_port, sizeof(addr->sin6_port)); // Copy the bound port (already in network byte order)

        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(addr->sin6_addr), addr_str, sizeof(addr_str));
    } else {
        log(ERROR, "Unsupported address family: %d", local_addr.ss_family);
        metrics_add_unsupported_input();
        return ERROR_CLIENT;
    }
    //send the response to the client
    const ssize_t num_bytes_sent = send(clnt_socket, response, local_addr.ss_family == AF_INET ? SOCKS5_IPV4_REQUEST: SOCKS5_IPV6_REQUEST, 0); //todo everything prior should be modularized because if ewould block the it will redo EVERYTHING
    if (num_bytes_sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            log(INFO, "send() would block on client socket %d, retrying later", clnt_socket);
            return REQUEST_WRITE; // Return to retry later
        }
        log(ERROR, "send() failed on client socket %d: %s", clnt_socket, strerror(errno));
        metrics_add_send_error();
        return ERROR_CLIENT;
    }
    if (num_bytes_sent == 0) {
        log(INFO, "Client socket %d closed connection", clnt_socket);
        return DONE;
    }
    if (num_bytes_sent < (local_addr.ss_family == AF_INET ? SOCKS5_IPV4_REQUEST: SOCKS5_IPV6_REQUEST) ) {
        return REQUEST_WRITE;
    }
    // Log the number of bytes sent
    buffer_reset(data->client_buffer); // Reset the client buffer for the next request
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
        data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return ERROR_CLIENT;
    }
    return RELAY_CLIENT;

}

unsigned handle_domain_request_read(struct selector_key *key) {
    client_data *data = key->data;

    size_t available_bytes;
    const uint8_t *read_ptr = buffer_read_ptr(data->client_buffer, &available_bytes);
    if (available_bytes < SOCKS5_REQUEST_HEADER_SIZE +  1) { // Check if we have enough bytes for the request header
        log(ERROR, "Incomplete SOCKS5 request header received");
        return REQUEST_READ; // Not enough data, wait for more
    }

    const uint8_t domain_length = read_ptr[ SOCKS5_REQUEST_HEADER_SIZE ]; // Longitud del nombre de dominio
    if (domain_length < 1 ) { // Validar longitud del dominio
        data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
        data->address_resolved = 1; // Indicate that the address is resolved (failed)
        return send_failure_response_client(key); // Send failure response to client
    }

    if (available_bytes < (size_t)domain_length + SOCKS5_REQUEST_HEADER_SIZE + PORT_SIZE + 1) { // domain_length + 2 bytes for port
        log(ERROR, "Incomplete domain name received");
        return REQUEST_READ;
    }
    buffer_read_adv(data->client_buffer, SOCKS5_REQUEST_HEADER_SIZE + 1);

    char domain_name[domain_length + 1];
    strncpy(domain_name, (char *)data->client_buffer->read, domain_length);
    domain_name[domain_length] = '\0'; // Asegurar que el nombre de dominio esté terminado en nulo
    buffer_read_adv(data->client_buffer, domain_length);
    const uint16_t port = ntohs(*(uint16_t *)data->client_buffer->read); // Leer el puerto
    buffer_read_adv(data->client_buffer, PORT_SIZE); // Avanzar el puntero de lectura
    data->destination.address_type = DOMAINNAME; // Guardar el tipo de dirección
    strncpy(data->destination.address.domain_name, domain_name, sizeof(data->destination.address.domain_name) - 1); // Guardar el nombre de dominio
    data->destination.address.domain_name[sizeof(data->destination.address.domain_name) - 1] = '\0'; // Asegurar que esté terminado en nulo
    data->destination.port = port; // Guardar el puerto

    data->current_user_conn.ip_destination.is_ipv6 = 0; // No es IPv6 si es domain name

    if (data->current_user_conn.destination_name) {
        free(data->current_user_conn.destination_name);
        data->current_user_conn.destination_name = NULL;
    }
    data->current_user_conn.destination_name = strdup(domain_name);

    data->current_user_conn.port_destination = port;

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", key->fd);
        data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
        data->address_resolved = 1;
        return send_failure_response_client(key);
    }

    buffer_reset(data->client_buffer); // Resetear el buffer para la siguiente lectura

    if ( setup_tcp_remote_socket(&data->destination, key) < 0) {
        log(ERROR, "Failed to setup TCP remote socket for domain name %s", domain_name);
        data->address_resolved = 1;
        return send_failure_response_client(key); // Send failure response to client
    }

    return AWAITING_RESOLUTION; // Cambiar al estado de escritura de solicitud
}

unsigned handle_ipv4_reques_read(struct selector_key *key) {
    client_data *data = key->data;
    size_t read_limit;
    uint8_t *read_ptr = buffer_read_ptr(data->client_buffer, &read_limit);
    if (read_limit < SOCKS5_REQUEST_HEADER_SIZE + IPV4_ADDR_SIZE + PORT_SIZE) {
        log(ERROR, "Incomplete IPv4 address received");
        return REQUEST_READ;
    }
    buffer_read_adv(data->client_buffer, SOCKS5_REQUEST_HEADER_SIZE); // Avanzar el puntero de lectura del buffer
    read_ptr = buffer_read_ptr(data->client_buffer, &read_limit);
    const uint32_t ip = ntohl(*(uint32_t *)read_ptr); // Leer la dirección IP
    buffer_read_adv(data->client_buffer, IPV4_ADDR_SIZE);
    read_ptr = buffer_read_ptr(data->client_buffer, &read_limit);
    const uint16_t port = ntohs(*(uint16_t *)read_ptr);
    buffer_read_adv(data->client_buffer, PORT_SIZE);

    data->destination.address_type = IPV4; // Guardar el tipo de dirección
    data->destination.address.ipv4 = ip; // Guardar la dirección IPv4
    data->destination.port = port; // Guardar el puerto
    data->current_user_conn.ip_destination.is_ipv6 = 0;
    data->current_user_conn.ip_destination.addr.ipv4.s_addr = htonl(data->destination.address.ipv4);
    data->current_user_conn.port_destination = data->destination.port;
    // === Convertir IPv4 a string ===
    char ip_str[INET_ADDRSTRLEN];  // 16 bytes
    struct in_addr inaddr = { .s_addr = htonl(ip) };
    if (inet_ntop(AF_INET, &inaddr, ip_str, sizeof(ip_str)) == NULL) {
        log(ERROR, "Failed to convert IP to string");
        return ERROR_CLIENT;
    }

    // Liberar anterior si existía
    if (data->current_user_conn.destination_name != NULL) {
        free(data->current_user_conn.destination_name);
    }

    // Guardar string duplicado
    data->current_user_conn.destination_name = strdup(ip_str);
    if (data->current_user_conn.destination_name == NULL) {
        log(ERROR, "Memory allocation failed for destination_name");
        return ERROR_CLIENT;
    }

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", key->fd);
        data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return send_failure_response_client(key); // Send failure response to client
    }

    buffer_reset(data->client_buffer); // Resetear el buffer para la siguiente lectura

    if ( setup_tcp_remote_socket(&data->destination, key) < 0) {
        return send_failure_response_client(key); // Send failure response to client
    }

    if (data->address_resolved) {
        return handle_request_write(key); // Cambiar al estado de escritura de solicitud
    }

    return REQUEST_WRITE;

}

unsigned handle_ipv6_request_read(struct selector_key *key) {
    client_data *data = key->data;
    size_t read_limit;
    buffer_read_ptr(data->client_buffer, &read_limit);
    if (read_limit < SOCKS5_REQUEST_HEADER_SIZE + IPV6_ADDR_SIZE + PORT_SIZE) { // 16 bytes de IP + 2 bytes de puerto
        log(ERROR, "Incomplete IPv4 address received");
        return REQUEST_READ;
    }
    buffer_read_adv(data->client_buffer, SOCKS5_REQUEST_HEADER_SIZE); // Avanzar el puntero de lectura del buffer
    char ipv6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, data->client_buffer->read, ipv6, sizeof(ipv6)); // Leer la dirección IPv6
    buffer_read_adv(data->client_buffer, IPV6_ADDR_SIZE); // Avanzar el puntero de lectura
    const uint16_t port = ntohs(*(uint16_t *)data->client_buffer->read); // Leer el puerto
    buffer_read_adv(data->client_buffer, PORT_SIZE); // Avanzar el puntero de lectura

    data->destination.address_type = IPV6; // Guardar el tipo de dirección
    struct in6_addr ipv6_addr = {0}; // Estructura para la dirección IPv6
    // Convertir la dirección IPv6 de texto a binario
    if (inet_pton(AF_INET6, ipv6, &ipv6_addr) != 1) {
        log(ERROR, "Invalid IPv6 address format: %s", ipv6);
        data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return send_failure_response_client(key); // Send failure response to client
    }
    data->destination.address.ipv6 = ipv6_addr; // Guardar la dirección IPv6
    data->destination.port = port; // Guardar el puerto
    data->current_user_conn.ip_destination.is_ipv6 = 1;
    data->current_user_conn.ip_destination.addr.ipv6 = data->destination.address.ipv6;
    data->current_user_conn.port_destination = data->destination.port;
    // === Convertir IP a string y guardar ===
    char ipv6_str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &ipv6_addr, ipv6_str, sizeof(ipv6_str)) == NULL) {
        log(ERROR, "Failed to convert IPv6 to string");
        return ERROR_CLIENT;
    }

    // Liberar si ya tenía nombre
    if (data->current_user_conn.destination_name != NULL) {
        free(data->current_user_conn.destination_name);
    }

    data->current_user_conn.destination_name = strdup(ipv6_str);
    if (data->current_user_conn.destination_name == NULL) {
        log(ERROR, "Memory allocation failed for destination_name");
        return ERROR_CLIENT;
    }

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", key->fd);
        data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return send_failure_response_client(key); // Send failure response to client
    }

    buffer_reset(data->client_buffer); // Resetear el buffer para la siguiente lectura

    if ( setup_tcp_remote_socket(&data->destination, key) < 0) {
        return send_failure_response_client(key); // Send failure response to client
    }

    if (data->address_resolved) {
        return handle_request_write(key); // Cambiar al estado de escritura de solicitud
    }
    return REQUEST_WRITE; // Cambiar al estado de escritura de solicitud


}

unsigned handle_request_read(struct selector_key *key) {
    const int clnt_socket = key->fd; // Socket del cliente
    client_data *data = key->data;

    // Recibir mensaje del cliente
    size_t write_limit;
    uint8_t *write_ptr = buffer_write_ptr(data->client_buffer, &write_limit);
    const ssize_t num_bytes_rcvd = recv(clnt_socket, write_ptr, write_limit, 0);
    if (num_bytes_rcvd < 0) {
        if ( errno == ECONNRESET) {
            log(INFO, "Client socket %d closed connection", clnt_socket);
            return RELAY_DONE; // El cliente cerró la conexión
        }
        log(ERROR, "recv() failed on client socket %d", clnt_socket);
        metrics_add_receive_error();
        return ERROR_CLIENT;
    }
    if (num_bytes_rcvd == 0) {
        log(INFO, "Client socket %d closed connection", clnt_socket);
        return DONE;
    }
    buffer_write_adv(data->client_buffer, num_bytes_rcvd); // Avanzar el puntero de escritura del buffer

    data->response_status = SOCKS5_SUCCEEDED; // Inicializar el estado de respuesta como éxito

    size_t read_available;

    const uint8_t * ptr = buffer_read_ptr(data->client_buffer, &read_available);
    // Procesar la solicitud del cliente
    if ( read_available < SOCKS5_REQUEST_HEADER_SIZE) { // Verificar si hay suficientes datos para procesar la solicitud
        log(ERROR, "Incomplete SOCKS request received");
        return REQUEST_READ; // Esperar más datos
    }
    const uint8_t socks_version = ptr[0];
    if (socks_version != SOCKS_VERSION) {
        log(ERROR, "Unsupported SOCKS version: %d", socks_version);
        data->response_status = SOCKS5_GENERAL_FAILURE; // Set error status
        metrics_add_unsupported_input();
        return send_failure_response_client(key); // Send failure response to client
    }
        // Leer el comando de la solicitud
    const uint8_t command = ptr[1];
    if (command != CONNECT) { // Solo soportamos el comando CONNECT (0x01)
        log(ERROR, "Unsupported command: %d", command);
        data->response_status = SOCKS5_COMMAND_NOT_SUPPORTED; // Set error status
        metrics_add_unsupported_input();
        return send_failure_response_client(key); // Send failure response to client
    }

    const uint8_t rsv = ptr[2]; // Reservado, debe ser 0x00
    if (rsv != RSV) {
        log(ERROR, "Invalid RSV field: %d", rsv);
        data->response_status = SOCKS5_GENERAL_FAILURE; // Set error status
        metrics_add_unsupported_input();
        return send_failure_response_client(key); // Send failure response to client
    }

        // Leer el tipo de dirección
    const uint8_t atyp = ptr[3];
    if (atyp == IPV4) { // Dirección IPv4
      return handle_ipv4_reques_read(key); // Manejar la lectura de la dirección IPv4
    }
    if (atyp == DOMAINNAME) { // Nombre de dominio
       return handle_domain_request_read(key); // Manejar la lectura del nombre de dominio
    }
    if (atyp == IPV6) { // Dirección IPv6
        return handle_ipv6_request_read(key);
    }
    log(ERROR, "Unsupported address type: %d", atyp);
    data->response_status = SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED; // Set error status
    metrics_add_unsupported_input();
    return send_failure_response_client(key); // Send failure response to client

}
unsigned handle_domain_resolve(struct selector_key *key, void *data) {
    client_data *client_data = key->data; // Get the client data from the key

    if (client_data->address_resolved) {
        if (client_data->response_status != SOCKS5_SUCCEEDED) {
            log(ERROR, "Address resolution already failed with status: %d", client_data->response_status);
            return send_failure_response_client(key); // Send failure response to client
        }
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            client_data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
            return send_failure_response_client(key); // Send failure response to client
        }
        return handle_request_write(key);
    }

    int remote_socket = -1; // Initialize remote socket
    int connected = 0; // Initialize connection status

    for (struct addrinfo *addr = client_data->remote_addrinfo; addr != NULL; addr = addr->ai_next) {
        client_data->remote_addrinfo = client_data->remote_addrinfo->ai_next; // Update the remote address info in client data
        remote_socket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (remote_socket < 0) {
            log(ERROR, "Failed to create socket for address %s: %s", addr_buffer, strerror(errno));
            client_data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
            continue;
        }

        if (selector_fd_set_nio(remote_socket) < 0) {
            log(ERROR, "Failed to set non-blocking mode for address %s: %s", addr_buffer, strerror(errno));
            client_data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
            return send_failure_response_client(key); // Send failure response to client
        }

        connected = connect(remote_socket, addr->ai_addr, addr->ai_addrlen);
        if (connected < 0) {
            if (errno != EINPROGRESS) { // Non-blocking connect
                log(ERROR, "connect() failed for address %s: %s", addr_buffer, strerror(errno));
                close(remote_socket);
                remote_socket = -1; // Reset to indicate failure

                const int connect_error = errno;
                set_response_status(client_data, connect_error); // Set the appropriate response status based on the error

                continue;
            }
        }

        if (!connected) {
            log(INFO, "Connected immediately");
            if (remote_socket_init(remote_socket, key, RELAY_REMOTE, OP_NOOP) < 0) {
                log(ERROR, "Failed to initialize remote socket for address %s", addr_buffer);
                client_data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
                return send_failure_response_client(key);
            }
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", key->fd);
                client_data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
                return send_failure_response_client(key);
            }
            return handle_request_write(key);
        }


        // Successfully connected to a new address
        if (remote_socket_init(remote_socket, key, RELAY_CONNECTING, OP_WRITE) < 0) {
            log(ERROR, "Failed to initialize remote socket for address %s", addr_buffer);
            client_data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
            return send_failure_response_client(key); // Send failure response to client
        }
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            client_data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
            return send_failure_response_client(key); // Send failure response to client
        }
        return DOMAIN_RESOLVING; // Change to the connecting state
    }

    log(ERROR, "Failed to connect to any remote address for client socket %d", key->fd);
    return send_failure_response_client(key); // Send failure response to client

}

