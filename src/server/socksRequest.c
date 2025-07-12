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

static char addrBuffer[MAX_ADDR_BUFFER];

int setRemoteAddress(const int remoteSocket,remoteData *rData) {

    struct sockaddr_storage remoteAddr;
    socklen_t remoteAddrLen = sizeof(remoteAddr);
    if (getsockname(remoteSocket, (struct sockaddr *)&remoteAddr, &remoteAddrLen) < 0) {
        log(ERROR, "Failed to get remote socket address: %s", strerror(errno));
        rData->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return -1; // TODO definir codigos de error
    }
    rData->remoteAddr = remoteAddr; // Set the remote address
    return 0;
}

unsigned connectWrite(struct selector_key * key) {
    remoteData *data = key->data;

    if (data->connectionReady) {
//        log(INFO, "Connection already ready for client socket %d", key->fd);
    } else {
        int error =0;
        socklen_t len = sizeof(error);
        if ( getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            log(ERROR, "getsockopt() failed: %s", strerror(errno));
            data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            if (selector_set_interest(key->s,data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", key->fd);
            }
            return RELAY_ERROR; // TODO definir codigos de error
        }

        if (error != 0) { //TODO: revisar pero parece funcionar, deberia cerrar el socket anterior?
            setResponseStatus(data->client, error);
            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for remote socket %d", key->fd);
            }
            if (data->client->destination.addressType == DOMAINNAME) {
                if (selector_notify_block(key->s, data->client_fd) != SELECTOR_SUCCESS) {
                    log(ERROR, "Failed to notify selector for client socket %d", key->fd);
                }
                data->client->addressResolved = 0; // Indicate that the callback is not ready
                return RELAY_CONNECTING; // Stay in the connecting state to retry the connection
            }

            if (selector_set_interest(key->s, data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", key->fd);
            }
            data->client->addressResolved = 1; // Indicate that the address is resolved (failed)
            return RELAY_ERROR;
        }
        data->connectionReady = 1;
    }

    if (setRemoteAddress(key->fd, data) < 0) {
        log(ERROR, "Failed to set remote address for client socket %d", key->fd);
        if (selector_set_interest(key->s, data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
        }
        return RELAY_ERROR; // TODO definir codigos de error
    }

    data->client->responseStatus = SOCKS5_SUCCEEDED; // Set response status to success
    data->client->addressResolved = 1;
    metrics_add_dns_resolution();
    if (data->client->destination.addressType == DOMAINNAME && selector_notify_block(key->s,data->client_fd) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to notify selector for client socket %d", key->fd);
        data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return RELAY_ERROR; // TODO definir codigos de error
    }
    if (data->client->destination.addressType != DOMAINNAME && selector_set_interest(key->s, data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", key->fd);
        data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return RELAY_ERROR; // TODO definir codigos de error
    }
    if (selector_set_interest(key->s, key->fd, OP_NOOP) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for remote socket %d", key->fd);
        data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return RELAY_ERROR; // TODO definir codigos de error
    }
    return RELAY_REMOTE; // Change to the relay remote state
}
void sendFailureResponse(int clntSocket, char *response) {
    response[3] = IPV4; // Address type (0 for IPv4)
    const ssize_t numBytesSent = send(clntSocket, response, 10, 0); // Send the failure response TODO magic number, yay
    if (numBytesSent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
    } else if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
    } else {
        log(INFO, "Sent failure response to client socket %d", clntSocket);
    }
}

unsigned handleRequestWrite(struct selector_key *key) {
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = key->data;

    char response[30] = {0}; // Buffer para la respuesta

    // Prepare the response to send to the client
    response[0] = SOCKS_VERSION; // Versión del protocolo SOCKS
    response[2] = RSV; // Reservado, debe ser 0x00

    // Get the local address info for the remote socket
    struct sockaddr_storage localAddr;
    socklen_t localAddrLen = sizeof(localAddr);
    if (data->responseStatus == SOCKS5_SUCCEEDED && getsockname(data->remoteSocket, (struct sockaddr *)&localAddr, &localAddrLen) < 0) {
        log(ERROR, "Failed to get local socket address: %s", strerror(errno));
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
    }

    response[1] = data->responseStatus; // Respuesta OK (no error)

    if (data->responseStatus != SOCKS5_SUCCEEDED) {
        log(ERROR, "Connection failed with status: %d", response[1]);
        sendFailureResponse(clntSocket, response); // Send failure response to client
        return ERROR_CLIENT; // TODO definir codigos de error
    }

    // Fill the response with the bound address and port that the client should use
    if (localAddr.ss_family == AF_INET) {
        // IPv4 address
        const struct sockaddr_in *addr = (struct sockaddr_in *)&localAddr;
        response[3] = IPV4; // Address type is IPv4
        memcpy(response + 4, &addr->sin_addr, sizeof(addr->sin_addr)); // Copy the bound IPv4 address
        memcpy(response + 8, &addr->sin_port, sizeof(addr->sin_port)); // Copy the bound port (already in network byte order)

        char addrStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr->sin_addr), addrStr, sizeof(addrStr));
//        log(INFO, "Bound to local IPv4 address: %s:%d", addrStr, ntohs(addr->sin_port));
    } else if (localAddr.ss_family == AF_INET6) {
        // IPv6 address
        const struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&localAddr;
        response[3] = IPV6; // Address type is IPv6
        memcpy(response + 4, &addr->sin6_addr, sizeof(addr->sin6_addr)); // Copy the bound IPv6 address
        memcpy(response + 20, &addr->sin6_port, sizeof(addr->sin6_port)); // Copy the bound port (already in network byte order)

        char addrStr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(addr->sin6_addr), addrStr, sizeof(addrStr));
//        log(INFO, "Bound to local IPv6 address: [%s]:%d", addrStr, ntohs(addr->sin6_port));
    } else { //todo this should not be possible, ostrich algorithm ftw
        log(ERROR, "Unsupported address family: %d", localAddr.ss_family);
        metrics_add_unsupported_input();
        return ERROR_CLIENT;
    }

    //send the response to the client
    const ssize_t numBytesSent = send(clntSocket, response, localAddr.ss_family == AF_INET ? 10: 22, 0); //fixme: puede ser esto, mandar largo exacto
    if (numBytesSent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        metrics_add_send_error();
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE; // TODO definir codigos de error
    }
    if (numBytesSent < (localAddr.ss_family == AF_INET ? 10: 22) ) { //todo magic numbers, yay
        return REQUEST_WRITE;
    }
    // Log the number of bytes sent
    buffer_reset(data->clientBuffer); // Reset the client buffer for the next request
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", clntSocket);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    return RELAY_CLIENT;

}
unsigned handleDomainRequestRead(struct selector_key *key) {
    clientData *data = key->data;

    const ssize_t domainLength = buffer_read(data->clientBuffer); // Longitud del nombre de dominio
    if (data->clientBuffer->write - data->clientBuffer->read < domainLength + 2) { // Longitud del dominio + 2 bytes de puerto
        log(ERROR, "Incomplete domain name received");
        return REQUEST_READ; // TODO definir codigos de error
    }
    char domainName[domainLength + 1];
    strncpy(domainName, (char *)data->clientBuffer->read, domainLength);
    domainName[domainLength] = '\0'; // Asegurar que el nombre de dominio esté terminado en nulo
    buffer_read_adv(data->clientBuffer, domainLength);
    const uint16_t port = ntohs(*(uint16_t *)data->clientBuffer->read); // Leer el puerto
    buffer_read_adv(data->clientBuffer, 2); // Avanzar el puntero de lectura
    data->destination.addressType = DOMAINNAME; // Guardar el tipo de dirección
    strncpy(data->destination.address.domainName, domainName, sizeof(data->destination.address.domainName) - 1); // Guardar el nombre de dominio
    data->destination.address.domainName[sizeof(data->destination.address.domainName) - 1] = '\0'; // Asegurar que esté terminado en nulo
    data->destination.port = port; // Guardar el puerto

    data->current_user_conn.ip_destination.is_ipv6 = 0; // No es IPv6 si es domain name

    if (data->current_user_conn.destination_name) {
        free(data->current_user_conn.destination_name);
    }
    data->current_user_conn.destination_name = strdup(domainName);

    data->current_user_conn.port_destination = port;

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", key->fd);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        data->addressResolved = 1;
        return REQUEST_WRITE; // TODO definir codigos de error
    }

    buffer_reset(data->clientBuffer); // Resetear el buffer para la siguiente lectura

    if ( setupTCPRemoteSocket(&data->destination, key) < 0) {
        log(ERROR, "Failed to setup TCP remote socket for domain name %s", domainName);
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
        }
        data->addressResolved = 1;
        return REQUEST_WRITE;
    }

    return DOMAIN_RESOLVING; // Cambiar al estado de escritura de solicitud
}

unsigned handleIPv4RequestRead(struct selector_key *key) {
    clientData *data = key->data;
    size_t readLimit;
    uint8_t *readPtr = buffer_read_ptr(data->clientBuffer, &readLimit);
    if (readLimit < 6) { // 4 bytes de IP + 2 bytes de puerto FIXME: esto creo que esta mal
        log(ERROR, "Incomplete IPv4 address received");
        return REQUEST_READ; // TODO definir codigos de error
    }
    uint32_t ip = ntohl(*(uint32_t *)readPtr); // Leer la dirección IP
    buffer_read_adv(data->clientBuffer, 4);
    readPtr = buffer_read_ptr(data->clientBuffer, &readLimit);
    const uint16_t port = ntohs(*(uint16_t *)readPtr);
    buffer_read_adv(data->clientBuffer, 2);

    data->destination.addressType = IPV4; // Guardar el tipo de dirección
    data->destination.address.ipv4 = ip; // Guardar la dirección IPv4
    data->destination.port = port; // Guardar el puerto
    data->current_user_conn.ip_destination.is_ipv6 = 0;
    data->current_user_conn.ip_destination.addr.ipv4.s_addr = htonl(data->destination.address.ipv4);
    data->current_user_conn.destination_name = NULL;
    data->current_user_conn.port_destination = data->destination.port;

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", key->fd);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return REQUEST_WRITE;
    }

    buffer_reset(data->clientBuffer); // Resetear el buffer para la siguiente lectura

    if ( setupTCPRemoteSocket(&data->destination, key) < 0) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
        }
    }

    return REQUEST_WRITE; // Cambiar al estado de escritura de solicitud
}

unsigned handleIPv6RequestRead(struct selector_key *key) {
    clientData *data = key->data;
    size_t readLimit;
   buffer_read_ptr(data->clientBuffer, &readLimit);
    if (readLimit < 18) { // 16 bytes de IP + 2 bytes de puerto
        log(ERROR, "Incomplete IPv4 address received");
        return REQUEST_READ; // TODO definir codigos de error
    }
    char ipv6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, data->clientBuffer->read, ipv6, sizeof(ipv6)); // Leer la dirección IPv6
    buffer_read_adv(data->clientBuffer, 16); // Avanzar el puntero de lectura
    const uint16_t port = ntohs(*(uint16_t *)data->clientBuffer->read); // Leer el puerto
    buffer_read_adv(data->clientBuffer, 2); // Avanzar el puntero de lectura

    data->destination.addressType = IPV6; // Guardar el tipo de dirección
    struct in6_addr ipv6Addr = {0}; // Estructura para la dirección IPv6
    // Convertir la dirección IPv6 de texto a binario
    if (inet_pton(AF_INET6, ipv6, &ipv6Addr) != 1) {
        log(ERROR, "Invalid IPv6 address format: %s", ipv6);
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    data->destination.address.ipv6 = ipv6Addr; // Guardar la dirección IPv6
    data->destination.port = port; // Guardar el puerto
    data->current_user_conn.ip_destination.is_ipv6 = 1;
    data->current_user_conn.ip_destination.addr.ipv6 = data->destination.address.ipv6;
    data->current_user_conn.destination_name = NULL;
    data->current_user_conn.port_destination = data->destination.port;

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", key->fd);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return REQUEST_WRITE;
    }

    buffer_reset(data->clientBuffer); // Resetear el buffer para la siguiente lectura

    if ( setupTCPRemoteSocket(&data->destination, key) < 0) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
        }
    }

    return REQUEST_WRITE; // Cambiar al estado de escritura de solicitud
}

unsigned handleRequestRead(struct selector_key *key) {
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = key->data;

    // Recibir mensaje del cliente
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    buffer_write_adv(data->clientBuffer, numBytesRcvd); // Avanzar el puntero de escritura del buffer
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d", clntSocket);
        metrics_add_receive_error();
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE; // TODO definir codigos de error
    }

    data->responseStatus = SOCKS5_SUCCEEDED; // Inicializar el estado de respuesta como éxito

    // Procesar la solicitud del cliente
    const uint8_t socksVersion = buffer_read(data->clientBuffer);
    if (socksVersion != SOCKS_VERSION) {
        log(ERROR, "Unsupported SOCKS version: %d", socksVersion);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set error status
        metrics_add_unsupported_input();
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clntSocket);
        }
        return REQUEST_WRITE;

    }
        // Leer el comando de la solicitud
    const uint8_t command = buffer_read(data->clientBuffer);
    if (command != CONNECT) { // Solo soportamos el comando CONNECT (0x01)
        log(ERROR, "Unsupported command: %d", command);
        data->responseStatus = SOCKS5_COMMAND_NOT_SUPPORTED; // Set error status
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clntSocket);
        }
        metrics_add_unsupported_input();
        return REQUEST_WRITE;
    }

    const uint8_t rsv = buffer_read(data->clientBuffer); // Reservado, debe ser 0x00
    if (rsv != RSV) {
        log(ERROR, "Invalid RSV field: %d", rsv);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set error status
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clntSocket);
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        }
        metrics_add_unsupported_input();
        return REQUEST_WRITE;
    }

        // Leer el tipo de dirección
    const uint8_t atyp = buffer_read(data->clientBuffer);
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
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", clntSocket);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
    }
    metrics_add_unsupported_input();
    return REQUEST_WRITE;

}
unsigned handleDomainResolve(struct selector_key *key) {
    clientData *data = key->data; // Get the client data from the key

    if (data->addressResolved) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        }
        return REQUEST_WRITE;
    }

    int remoteSocket = -1; // Initialize remote socket

    for (struct addrinfo *addr = data->remoteAddrInfo; addr != NULL; addr = addr->ai_next) { //TODO this for loop could use modularization, repeated code in setupRemoteTCPSocket
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

        if (connect(remoteSocket, addr->ai_addr, addr->ai_addrlen) < 0) {
            if (errno != EINPROGRESS) { // Non-blocking connect
                log(ERROR, "connect() failed for address %s: %s", addrBuffer, strerror(errno));
                close(remoteSocket);
                remoteSocket = -1; // Reset to indicate failure

                int connectError = errno;
                setResponseStatus(data, connectError); // Set the appropriate response status based on the error

                continue;
            }
        }

        // Successfully connected to a new address
        if (remoteSocketInit(remoteSocket, key) < 0) {
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

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", key->fd);
    }
    log(ERROR, "Failed to connect to any remote address for client socket %d", key->fd);
    return REQUEST_WRITE;

}

