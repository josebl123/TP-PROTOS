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
static char addrBuffer[MAX_ADDR_BUFFER];

int setRemoteAddress(const int remoteSocket,remoteData *rData) {

    struct sockaddr_storage remoteAddr;
    socklen_t remoteAddrLen = sizeof(remoteAddr);
    if (getsockname(remoteSocket, (struct sockaddr *)&remoteAddr, &remoteAddrLen) < 0) {
        log(ERROR, "Failed to get remote socket address: %s", strerror(errno));
        rData->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return -1;
    }
    rData->remoteAddr = remoteAddr; // Set the remote address
    return 0;
}

unsigned connectWrite(struct selector_key * key) {
    remoteData *data = key->data;

    if (!data->connectionReady) {
        int error =0;
        socklen_t len = sizeof(error);
        clock_gettime(CLOCK_MONOTONIC, & data->client->last_activity);
        if ( getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            log(ERROR, "getsockopt() failed: %s", strerror(errno));
            data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
//            data->client->addressResolved = 1; // Indicate that the callback is not ready
//            if (data->client->destination.addressType == DOMAINNAME) {
//                if (selector_notify_block(key->s, data->client_fd) != SELECTOR_SUCCESS) {
//                    log(ERROR, "Failed to notify selector for client socket %d", key->fd);
//                }
//                log(ERROR, "Failed to notify selector for client socket %d", key->fd);
//            }else {
//                if (selector_set_interest(key->s, data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
//                    log(ERROR, "Failed to set interest for client socket %d", key->fd);
//                }
//            }
            return sendFailureResponseRemote(key); // Change to the relay error state
        }

        if (error != 0) {
            setResponseStatus(data->client, error);
            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for remote socket %d", key->fd);
                return sendFailureResponseRemote(key);
            }
            if (data->client->destination.addressType == DOMAINNAME) {
                if (selector_notify_block(key->s, data->client_fd) != SELECTOR_SUCCESS) {
                    log(ERROR, "Failed to notify selector for client socket %d", key->fd);
                    return sendFailureResponseRemote(key);
                }
                data->client->addressResolved = 0; // Indicate that the callback is not ready
                return RELAY_CONNECTING; // Stay in the connecting state to retry the connection
            }

            return sendFailureResponseRemote(key); // Change to the relay error state

//            if (selector_set_interest(key->s, data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
//                log(ERROR, "Failed to set interest for client socket %d", key->fd);
//                return sendFailureResponseRemote(key);
//            }
//            data->client->addressResolved = 1; // Indicate that the address is resolved (failed)
//            return RELAY_ERROR;
        }
        data->connectionReady = 1;
    }

    data->client->responseStatus = SOCKS5_SUCCEEDED; // Set response status to success
    data->client->addressResolved = 1;
    metrics_add_dns_resolution();
    if (data->client->destination.addressType == DOMAINNAME) {
        if (selector_notify_block(key->s,data->client_fd) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to notify selector for client socket %d", key->fd);
            data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            return sendFailureResponseRemote(key);
        }
    } else {
        if (selector_set_interest(key->s, data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            return sendFailureResponseRemote(key);
        }
    }
    if (selector_set_interest(key->s, key->fd, OP_NOOP) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for remote socket %d", key->fd);
        data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return sendFailureResponseRemote(key);
    }
    return RELAY_REMOTE; // Change to the relay remote state
}

unsigned sendFailureResponse(clientData *data, int clntSocket, unsigned error, struct selector_key *key) {

    char response[SOCKS5_MAX_REQUEST_RESPONSE] = {0}; // Buffer for the response
    response[0] = SOCKS_VERSION; // Versión del protocolo SOCKS
    response[1] = data->responseStatus; // Respuesta de error
    response[2] = RSV; // Reservado, debe ser 0x00
    response[3] = IPV4; // Address type (0 for IPv4)

    const ssize_t numBytesSent = send(clntSocket, response, SOCKS5_IPV4_REQUEST, 0); // Send the failure response
    if (numBytesSent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            log(INFO, "send() would block on client socket %d, retrying later", clntSocket);
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", clntSocket);
                return error;
            }
            return FAILURE_RESPONSE; // Return to retry later
        }
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
    } else if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
    } else {
        log(INFO, "Sent failure response to client socket %d", clntSocket);
    }
    return error;
}

unsigned sendFailureResponseClient(struct selector_key *key) {
    return sendFailureResponse(key->data, key->fd, ERROR_CLIENT, key);
}

unsigned sendFailureResponseRemote(struct selector_key *key) {
    const remoteData *data = key->data;
    return sendFailureResponse(data->client, data->client_fd, RELAY_ERROR, key);
}

unsigned handleRequestWrite(struct selector_key *key) {
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = key->data;

    if (data->responseStatus != SOCKS5_SUCCEEDED) {
        log(ERROR, "Connection failed with status: %d", data->responseStatus);
        return sendFailureResponseClient(key); // Send failure response to client
    }

    // Get the local address info for the remote socket
    struct sockaddr_storage localAddr;
    socklen_t localAddrLen = sizeof(localAddr);
    if (getsockname(data->remoteSocket, (struct sockaddr *)&localAddr, &localAddrLen) < 0) {
        log(ERROR, "Failed to get local socket address: %s", strerror(errno));
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return sendFailureResponseClient(key); // Send failure response to client
    }

    char response[SOCKS5_MAX_REQUEST_RESPONSE] = {0}; // Buffer para la respuesta

    // Prepare the response to send to the client
    response[0] = SOCKS_VERSION; // Versión del protocolo SOCKS
    response[1] = data->responseStatus; // Respuesta OK (no error)
    response[2] = RSV; // Reservado, debe ser 0x00

    // Fill the response with the bound address and port that the client should use
    if (localAddr.ss_family == AF_INET) {
        // IPv4 address
        const struct sockaddr_in *addr = (struct sockaddr_in *)&localAddr;
        response[3] = IPV4; // Address type is IPv4
        memcpy(response + REQUEST_HEADER, &addr->sin_addr, sizeof(addr->sin_addr)); // Copy the bound IPv4 address
        memcpy(response + REQUEST_HEADER + IPV4_ADDR_SIZE, &addr->sin_port, sizeof(addr->sin_port)); // Copy the bound port (already in network byte order)

        char addrStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr->sin_addr), addrStr, sizeof(addrStr));
    } else if (localAddr.ss_family == AF_INET6) {
        // IPv6 address
        const struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&localAddr;
        response[3] = IPV6; // Address type is IPv6
        memcpy(response + REQUEST_HEADER, &addr->sin6_addr, sizeof(addr->sin6_addr)); // Copy the bound IPv6 address
        memcpy(response + REQUEST_HEADER + IPV6_ADDR_SIZE, &addr->sin6_port, sizeof(addr->sin6_port)); // Copy the bound port (already in network byte order)

        char addrStr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(addr->sin6_addr), addrStr, sizeof(addrStr));
    } else {
        log(ERROR, "Unsupported address family: %d", localAddr.ss_family);
        metrics_add_unsupported_input();
        return ERROR_CLIENT;
    }
    //send the response to the client
    const ssize_t numBytesSent = send(clntSocket, response, localAddr.ss_family == AF_INET ? SOCKS5_IPV4_REQUEST: SOCKS5_IPV6_REQUEST, 0); //todo everything prior should be modularized because if ewould block the it will redo EVERYTHING
    if (numBytesSent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            log(INFO, "send() would block on client socket %d, retrying later", clntSocket);
            return REQUEST_WRITE; // Return to retry later
        }
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        metrics_add_send_error();
        return ERROR_CLIENT;
    }
    if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }
    if (numBytesSent < (localAddr.ss_family == AF_INET ? SOCKS5_IPV4_REQUEST: SOCKS5_IPV6_REQUEST) ) { //todo should preserve the to-send bytes in a buffer?
        return REQUEST_WRITE;
    }
    // Log the number of bytes sent
    buffer_reset(data->clientBuffer); // Reset the client buffer for the next request
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", clntSocket);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return ERROR_CLIENT;
    }
    return RELAY_CLIENT;

}

unsigned handleDomainRequestRead(struct selector_key *key) {
    clientData *data = key->data;

    size_t availableBytes;
    const uint8_t *readPtr = buffer_read_ptr(data->clientBuffer, &availableBytes);
    if (availableBytes < SOCKS5_REQUEST_HEADER_SIZE +  1) { // Check if we have enough bytes for the request header
        log(ERROR, "Incomplete SOCKS5 request header received");
        return REQUEST_READ; // Not enough data, wait for more
    }

    const uint8_t domainLength = readPtr[ SOCKS5_REQUEST_HEADER_SIZE ]; // Longitud del nombre de dominio
    if (domainLength < 1 ) { // Validar longitud del dominio
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        data->addressResolved = 1; // Indicate that the address is resolved (failed)
        return sendFailureResponseClient(key); // Send failure response to client
    }

    if (availableBytes < (size_t)domainLength + SOCKS5_REQUEST_HEADER_SIZE + PORT_SIZE + 1) { // domainLength + 2 bytes for port
        log(ERROR, "Incomplete domain name received");
        return REQUEST_READ;
    }
    buffer_read_adv(data->clientBuffer, SOCKS5_REQUEST_HEADER_SIZE + 1);

    char domainName[domainLength + 1];
    strncpy(domainName, (char *)data->clientBuffer->read, domainLength);
    domainName[domainLength] = '\0'; // Asegurar que el nombre de dominio esté terminado en nulo
    buffer_read_adv(data->clientBuffer, domainLength);
    const uint16_t port = ntohs(*(uint16_t *)data->clientBuffer->read); // Leer el puerto
    buffer_read_adv(data->clientBuffer, PORT_SIZE); // Avanzar el puntero de lectura
    data->destination.addressType = DOMAINNAME; // Guardar el tipo de dirección
    strncpy(data->destination.address.domainName, domainName, sizeof(data->destination.address.domainName) - 1); // Guardar el nombre de dominio
    data->destination.address.domainName[sizeof(data->destination.address.domainName) - 1] = '\0'; // Asegurar que esté terminado en nulo
    data->destination.port = port; // Guardar el puerto

    data->current_user_conn.ip_destination.is_ipv6 = 0; // No es IPv6 si es domain name

    if (data->current_user_conn.destination_name) {
        free(data->current_user_conn.destination_name);
        data->current_user_conn.destination_name = NULL;
    }
    data->current_user_conn.destination_name = strdup(domainName);

    data->current_user_conn.port_destination = port;

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", key->fd);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        data->addressResolved = 1;
        return sendFailureResponseClient(key);
    }

    buffer_reset(data->clientBuffer); // Resetear el buffer para la siguiente lectura

    if ( setupTCPRemoteSocket(&data->destination, key) < 0) {
        log(ERROR, "Failed to setup TCP remote socket for domain name %s", domainName);
        data->addressResolved = 1;
        return sendFailureResponseClient(key); // Send failure response to client
    }

    return DOMAIN_RESOLVING; // Cambiar al estado de escritura de solicitud
}

unsigned handleIPv4RequestRead(struct selector_key *key) {
    clientData *data = key->data;
    size_t readLimit;
    uint8_t *readPtr = buffer_read_ptr(data->clientBuffer, &readLimit);
    if (readLimit < SOCKS5_REQUEST_HEADER_SIZE + IPV4_ADDR_SIZE + PORT_SIZE) {
        log(ERROR, "Incomplete IPv4 address received");
        return REQUEST_READ;
    }
    buffer_read_adv(data->clientBuffer, SOCKS5_REQUEST_HEADER_SIZE); // Avanzar el puntero de lectura del buffer
    readPtr = buffer_read_ptr(data->clientBuffer, &readLimit);
    const uint32_t ip = ntohl(*(uint32_t *)readPtr); // Leer la dirección IP
    buffer_read_adv(data->clientBuffer, IPV4_ADDR_SIZE);
    readPtr = buffer_read_ptr(data->clientBuffer, &readLimit);
    const uint16_t port = ntohs(*(uint16_t *)readPtr);
    buffer_read_adv(data->clientBuffer, PORT_SIZE);

    data->destination.addressType = IPV4; // Guardar el tipo de dirección
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
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return sendFailureResponseClient(key); // Send failure response to client
    }

    buffer_reset(data->clientBuffer); // Resetear el buffer para la siguiente lectura

    if ( setupTCPRemoteSocket(&data->destination, key) < 0) {
        return sendFailureResponseClient(key); // Send failure response to client
    }

    if (data->addressResolved) {
        return handleRequestWrite(key); // Cambiar al estado de escritura de solicitud
    }

    return REQUEST_WRITE;

}

unsigned handleIPv6RequestRead(struct selector_key *key) {
    clientData *data = key->data;
    size_t readLimit;
    buffer_read_ptr(data->clientBuffer, &readLimit);
    if (readLimit < SOCKS5_REQUEST_HEADER_SIZE + IPV6_ADDR_SIZE + PORT_SIZE) { // 16 bytes de IP + 2 bytes de puerto
        log(ERROR, "Incomplete IPv4 address received");
        return REQUEST_READ;
    }
    buffer_read_adv(data->clientBuffer, SOCKS5_REQUEST_HEADER_SIZE); // Avanzar el puntero de lectura del buffer
    char ipv6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, data->clientBuffer->read, ipv6, sizeof(ipv6)); // Leer la dirección IPv6
    buffer_read_adv(data->clientBuffer, IPV6_ADDR_SIZE); // Avanzar el puntero de lectura
    const uint16_t port = ntohs(*(uint16_t *)data->clientBuffer->read); // Leer el puerto
    buffer_read_adv(data->clientBuffer, PORT_SIZE); // Avanzar el puntero de lectura

    data->destination.addressType = IPV6; // Guardar el tipo de dirección
    struct in6_addr ipv6Addr = {0}; // Estructura para la dirección IPv6
    // Convertir la dirección IPv6 de texto a binario
    if (inet_pton(AF_INET6, ipv6, &ipv6Addr) != 1) {
        log(ERROR, "Invalid IPv6 address format: %s", ipv6);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return sendFailureResponseClient(key); // Send failure response to client
    }
    data->destination.address.ipv6 = ipv6Addr; // Guardar la dirección IPv6
    data->destination.port = port; // Guardar el puerto
    data->current_user_conn.ip_destination.is_ipv6 = 1;
    data->current_user_conn.ip_destination.addr.ipv6 = data->destination.address.ipv6;
    data->current_user_conn.port_destination = data->destination.port;
    // === Convertir IP a string y guardar ===
    char ipv6Str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &ipv6Addr, ipv6Str, sizeof(ipv6Str)) == NULL) {
        log(ERROR, "Failed to convert IPv6 to string");
        return ERROR_CLIENT;
    }

    // Liberar si ya tenía nombre
    if (data->current_user_conn.destination_name != NULL) {
        free(data->current_user_conn.destination_name);
    }

    data->current_user_conn.destination_name = strdup(ipv6Str);
    if (data->current_user_conn.destination_name == NULL) {
        log(ERROR, "Memory allocation failed for destination_name");
        return ERROR_CLIENT;
    }

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", key->fd);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return sendFailureResponseClient(key); // Send failure response to client
    }

    buffer_reset(data->clientBuffer); // Resetear el buffer para la siguiente lectura

    if ( setupTCPRemoteSocket(&data->destination, key) < 0) {
        return sendFailureResponseClient(key); // Send failure response to client
    }

    if (data->addressResolved) {
        return handleRequestWrite(key); // Cambiar al estado de escritura de solicitud
    }
    return REQUEST_WRITE; // Cambiar al estado de escritura de solicitud


}

unsigned handleRequestRead(struct selector_key *key) {
    const int clntSocket = key->fd; // Socket del cliente
    clientData *data = key->data;

    // Recibir mensaje del cliente
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    if (numBytesRcvd < 0) {
        if ( errno == ECONNRESET) {
            log(INFO, "Client socket %d closed connection", clntSocket);
            return RELAY_DONE; // El cliente cerró la conexión
        }
        log(ERROR, "recv() failed on client socket %d", clntSocket);
        metrics_add_receive_error();
        return ERROR_CLIENT;
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }
    buffer_write_adv(data->clientBuffer, numBytesRcvd); // Avanzar el puntero de escritura del buffer

    data->responseStatus = SOCKS5_SUCCEEDED; // Inicializar el estado de respuesta como éxito

    size_t readAvailable;

    const uint8_t * ptr = buffer_read_ptr(data->clientBuffer, &readAvailable);
    // Procesar la solicitud del cliente
    if ( readAvailable < SOCKS5_REQUEST_HEADER_SIZE) { // Verificar si hay suficientes datos para procesar la solicitud
        log(ERROR, "Incomplete SOCKS request received");
        return REQUEST_READ; // Esperar más datos
    }
    const uint8_t socksVersion = ptr[0];
    if (socksVersion != SOCKS_VERSION) {
        log(ERROR, "Unsupported SOCKS version: %d", socksVersion);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set error status
        metrics_add_unsupported_input();
        return sendFailureResponseClient(key); // Send failure response to client
    }
        // Leer el comando de la solicitud
    const uint8_t command = ptr[1];
    if (command != CONNECT) { // Solo soportamos el comando CONNECT (0x01)
        log(ERROR, "Unsupported command: %d", command);
        data->responseStatus = SOCKS5_COMMAND_NOT_SUPPORTED; // Set error status
        metrics_add_unsupported_input();
        return sendFailureResponseClient(key); // Send failure response to client
    }

    const uint8_t rsv = ptr[2]; // Reservado, debe ser 0x00
    if (rsv != RSV) {
        log(ERROR, "Invalid RSV field: %d", rsv);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set error status
        metrics_add_unsupported_input();
        return sendFailureResponseClient(key); // Send failure response to client
    }

        // Leer el tipo de dirección
    const uint8_t atyp = ptr[3];
    if (atyp == IPV4) { // Dirección IPv4
      return handleIPv4RequestRead(key); // Manejar la lectura de la dirección IPv4
    }
    if (atyp == DOMAINNAME) { // Nombre de dominio
       return handleDomainRequestRead(key); // Manejar la lectura del nombre de dominio
    }
    if (atyp == IPV6) { // Dirección IPv6
        return handleIPv6RequestRead(key);
    }
    log(ERROR, "Unsupported address type: %d", atyp);
    data->responseStatus = SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED; // Set error status
    metrics_add_unsupported_input();
    return sendFailureResponseClient(key); // Send failure response to client

}
unsigned handleDomainResolve(struct selector_key *key) {
    clientData *data = key->data; // Get the client data from the key

    if (data->addressResolved) {
        if (data->responseStatus != SOCKS5_SUCCEEDED) {
            log(ERROR, "Address resolution already failed with status: %d", data->responseStatus);
            return sendFailureResponseClient(key); // Send failure response to client
        }
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            return sendFailureResponseClient(key); // Send failure response to client
        }
        return handleRequestWrite(key);
    }

    int remoteSocket = -1; // Initialize remote socket
    int connected = 0; // Initialize connection status

    for (struct addrinfo *addr = data->remoteAddrInfo; addr != NULL; addr = addr->ai_next) {
        data->remoteAddrInfo = data->remoteAddrInfo->ai_next; // Update the remote address info in client data
        remoteSocket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (remoteSocket < 0) {
            log(ERROR, "Failed to create socket for address %s: %s", addrBuffer, strerror(errno));
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            continue;
        }

        if (selector_fd_set_nio(remoteSocket) < 0) {
            log(ERROR, "Failed to set non-blocking mode for address %s: %s", addrBuffer, strerror(errno));
            close(remoteSocket);
            remoteSocket = -1; // Reset to indicate failure
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            continue;
        }

        connected = connect(remoteSocket, addr->ai_addr, addr->ai_addrlen);
        if (connected < 0) {
            if (errno != EINPROGRESS) { // Non-blocking connect
                log(ERROR, "connect() failed for address %s: %s", addrBuffer, strerror(errno));
                close(remoteSocket);
                remoteSocket = -1; // Reset to indicate failure

                const int connectError = errno;
                setResponseStatus(data, connectError); // Set the appropriate response status based on the error

                continue;
            }
        }

        if (!connected) {
            log(INFO, "Connected immediately");
            if (remoteSocketInit(remoteSocket, key, RELAY_REMOTE, OP_NOOP) < 0) {
                log(ERROR, "Failed to initialize remote socket for address %s", addrBuffer);
                close(remoteSocket);
                remoteSocket = -1;
                data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
                continue;
            }
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", key->fd);
                close(remoteSocket); //todo should be unregistered from selector, bear in mind edge case that next is null, double unregister will happen
                remoteSocket = -1; // Reset to indicate failure
                data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
                continue;
            }
            return handleRequestWrite(key);
        }


        // Successfully connected to a new address
        if (remoteSocketInit(remoteSocket, key, RELAY_CONNECTING, OP_WRITE) < 0) {
            log(ERROR, "Failed to initialize remote socket for address %s", addrBuffer);
            close(remoteSocket);
            remoteSocket = -1;
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            continue;
        }
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            close(remoteSocket); //todo should be unregistered from selector, bear in mind edge case that next is null, double unregister will happen
            remoteSocket = -1; // Reset to indicate failure
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            continue;
        }
        return DOMAIN_RESOLVING; // Change to the connecting state
    }

    log(ERROR, "Failed to connect to any remote address for client socket %d", key->fd);
    return sendFailureResponseClient(key); // Send failure response to client

}

