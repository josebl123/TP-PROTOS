#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "../utils/logger.h"
#include "../utils/util.h"
#include "tcpServerUtil.h"
#include "socksAuth.h"
#include "socksRelay.h"

#include "../selector.h"
#include "../buffer.h"


#define MAXPENDING 5 // Maximum outstanding connection requests
#define MAX_ADDR_BUFFER 128
#define BUFSIZE 1024  // Buffer size for client data


#define CONNECT 1
#define RSV 0

void socks5_relay_read(struct selector_key *key);
void socks5_relay_write(struct selector_key *key);

static char addrBuffer[MAX_ADDR_BUFFER];
/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
void handleTcpClose(  struct selector_key *key) {
    log(INFO, "Closing client socket %d", key->fd);
    clientData *data =  key->data;
    selector_unregister_fd( key->s,data->remoteSocket); // Desregistrar el socket remoto

    free(data->clientBuffer->data);
    free(data->clientBuffer);
    free(data);
    // Close the client socket
    close(key->fd);
}
void handleRemoteClose( struct selector_key *key) {
    log(INFO, "Closing remote socket %d", key->fd);
    remoteData *data = key->data;

    free(data->stm);
    free(data->buffer->data); // Liberar memoria del buffer
    free(data->buffer); // Liberar memoria del buffer
    free(data); // Liberar memoria de remoteData
    close(key->fd);
}
void clientClose(const unsigned state, struct selector_key *key) {
    if (state == ERROR_CLIENT) {
        log(ERROR, "Closing remote socket %d due to error", key->fd);
    } else {
        log(INFO, "Closing remote socket %d after completion", key->fd);
    }
    selector_unregister_fd(key->s, key->fd); // Desregistrar el socket del selector
    close(key->fd); // Cerrar el socket del cliente
}
void remoteClose(const unsigned state, struct selector_key *key) {
    if (state == RELAY_ERROR) {
        log(ERROR, "Closing remote socket %d due to error", key->fd);
    } else {
        log(INFO, "Closing remote socket %d after completion", key->fd);
    }
    selector_unregister_fd(key->s, key->fd); // Desregistrar el socket del selector
    close(key->fd); // Cerrar el socket remoto
}
 static const struct state_definition states[] = {
    [HELLO_READ] =    { .state = HELLO_READ, .on_read_ready = handleHelloRead },
    [HELLO_WRITE] =   { .state = HELLO_WRITE, .on_write_ready = handleHelloWrite },
    [AUTH_READ] =     { .state = AUTH_READ, .on_read_ready = handleAuthRead },
    [AUTH_WRITE] =    { .state = AUTH_WRITE, .on_write_ready = handleAuthWrite },
    [REQUEST_READ] =  { .state = REQUEST_READ, .on_read_ready = handleRequestRead },
    [REQUEST_WRITE] = { .state = REQUEST_WRITE, .on_write_ready = handleRequestWrite },
    [DONE] =          { .state = DONE, .on_arrival = clientClose },
    [ERROR_CLIENT] =  { .state = ERROR_CLIENT,.on_arrival = clientClose},
    [RELAY_CLIENT] = { .state = RELAY_CLIENT, .on_read_ready = handleRelayClientRead,.on_write_ready = handleRelayClientWrite  },
};

static const struct state_definition relay_states[] = {
    [RELAY_CONNECTING] = { .state = RELAY_CONNECTING, .on_write_ready = connectWrite }, // This state handles the connection to the remote server
    [RELAY_REMOTE] = { .state = RELAY_REMOTE, .on_read_ready = handleRelayRemoteRead, .on_write_ready = handleRelayRemoteWrite },
    [RELAY_DONE] = { .state = RELAY_DONE, .on_arrival = remoteClose },
    [RELAY_ERROR] = { .state = RELAY_ERROR, .on_arrival = remoteClose },
};

 static const fd_handler client_handler = {
    .handle_read = socks5_read, // Initial read handler
    .handle_write = socks5_write, // Initial write handler
    .handle_block = NULL, // Not used in this case
    .handle_close =  handleTcpClose// Close handler
};
static const fd_handler relay_handler = {
    .handle_read = socks5_relay_read, // Relay read handler
    .handle_write = socks5_relay_write, // Relay write handler
    .handle_block = NULL, // Not used in this case
    .handle_close = handleRemoteClose // Relay close handler
};


int setupTCPServerSocket(const char *service) {
    // Construct the server address structure
    struct addrinfo addrCriteria = {0};                   // Criteria for address match
    addrCriteria.ai_family = AF_UNSPEC;             // Any address family
    addrCriteria.ai_flags = AI_PASSIVE;             // Accept on any address/port
    addrCriteria.ai_socktype = SOCK_STREAM;         // Only stream sockets
    addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

    struct addrinfo *servAddr; 			// List of server addresses
    const int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr);
    if (rtnVal != 0) {
        log(FATAL, "getaddrinfo() failed %s", gai_strerror(rtnVal));
        return -1;
    }

    int servSock = -1;
    // Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio, sin especificar una IP en particular
    // Iteramos y hacemos el bind por alguna de ellas, la primera que funcione, ya sea la general para IPv4 (0.0.0.0) o IPv6 (::/0) .
    // Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
    for (const struct addrinfo *addr = servAddr; addr != NULL && servSock == -1; addr = addr->ai_next) {
        errno = 0;
        // Create a TCP socket
        servSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (servSock < 0) {
            log(DEBUG, "Cant't create socket on %s : %s ", printAddressPort(addr, addrBuffer), strerror(errno));
            continue;       // Socket creation failed; try next address
        }

       setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)); // Allow reuse of address

        // Bind to ALL the address and set socket to listen
        if (bind(servSock, addr->ai_addr, addr->ai_addrlen) == 0 && listen(servSock, MAXPENDING) == 0) {
            // Print local address of socket
            struct sockaddr_storage localAddr;
            socklen_t addrSize = sizeof(localAddr);
            if (getsockname(servSock, (struct sockaddr *) &localAddr, &addrSize) >= 0) {
                printSocketAddress((struct sockaddr *) &localAddr, addrBuffer);
                log(INFO, "Binding to %s", addrBuffer);
            }
        } else {
            log(DEBUG, "Cant't bind %s", strerror(errno));
            close(servSock);  // Close and try with the next one
            servSock = -1;
        }
    }

    freeaddrinfo(servAddr);

    return servSock;
}
struct state_machine * createRemoteStateMachine() {
    struct state_machine *stm = malloc(sizeof(struct state_machine));
    if (stm == NULL) {
        log(ERROR, "Failed to allocate memory for remote state machine");
        return NULL;
    }
    stm->initial = RELAY_CONNECTING; // Initial state for remote relay
    stm->states = relay_states; // Use the relay states defined above
    stm->max_state = RELAY_ERROR; // Total number of states in the relay machine
    stm_init(stm);
    return stm;
}
 int remoteSocketInit(const int remoteSocket, struct selector_key *key, const struct addrinfo *remoteAddrInfo) {
    clientData *data = key->data;

    buffer *remoteBuffer = malloc(sizeof(buffer)); // Create a buffer for the remote socket
    if (remoteBuffer == NULL) {
        log(ERROR, "Failed to allocate memory for remote buffer");
        data->responseStatus = SOCKS5_GENERAL_FAILURE;
        return -1; // TODO definir codigos de error
    }
    remoteBuffer->data = malloc(BUFSIZE); // Allocate memory for the buffer data
    if (remoteBuffer->data == NULL) {
        log(ERROR, "Failed to allocate memory for remote buffer data");
        free(remoteBuffer);
        data->responseStatus = SOCKS5_GENERAL_FAILURE;
        return -1; // TODO definir codigos de error
    }
    buffer_init(remoteBuffer, BUFSIZE, remoteBuffer->data); // Initialize the buffer with a size //TODO put this buffer somewhere to read from destination
    remoteData *rData = malloc(sizeof(remoteData)); // Create a remoteData structure
    if (rData == NULL) {
        log(ERROR, "Failed to allocate memory for remoteData");
        free(remoteBuffer->data);
        free(remoteBuffer);
        data->responseStatus = SOCKS5_GENERAL_FAILURE;
        return -1; // TODO definir codigos de error
    }

    log(INFO, "Initializing remote socket %d for client %d", remoteSocket, key->fd);

    rData->client_fd = key->fd; // Set the remote socket file descriptor
    rData->client = data; // Set the client data
    rData->buffer = remoteBuffer; // Set the buffer for the remote socket
    rData->stm = createRemoteStateMachine(); // Create the state machine for the remote socket
    data->remoteBuffer = remoteBuffer; // Assign the remote buffer to client data
    data->remoteSocket = remoteSocket; // Store the remote socket in client data


    rData->remoteAddrInfo = remoteAddrInfo; // Store the remote address info for potential retries

    // Register the remote socket with the selector
    if (selector_register(key->s, remoteSocket, &relay_handler, OP_WRITE, rData) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to register remote socket %d with selector", remoteSocket);
        free(rData->buffer->data); // Free the buffer data
        free(rData->buffer); // Free the buffer
        free(rData); // Free the remoteData structure
        data->responseStatus = SOCKS5_GENERAL_FAILURE;
        return -1; // TODO definir codigos de error
    }

    log(INFO, "Remote socket %d initialized and registered with selector for client %d", remoteSocket, key->fd);

    return 0;
}
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

void setResponseStatus(clientData *data, int error) {
    switch (error) {
        case EACCES:
        log(ERROR, "Connection not allowed for remote address: %s", strerror(errno));
            data->responseStatus = SOCKS5_CONNECTION_NOT_ALLOWED;
            break;
        case ENETUNREACH:
        log(ERROR, "Network unreachable for remote address: %s", strerror(errno));
            data->responseStatus = SOCKS5_NETWORK_UNREACHABLE;
            break;
        case EHOSTDOWN:
        case EHOSTUNREACH:
        log(ERROR, "Host unreachable or host down for remote address: %s", strerror(errno));
            data->responseStatus = SOCKS5_HOST_UNREACHABLE;
            break;
        case ECONNREFUSED:
        log(ERROR, "Connection refused for remote address: %s", strerror(errno));
            data->responseStatus = SOCKS5_CONNECTION_REFUSED;
            break;
        case ETIMEDOUT:
        log(ERROR, "Connection timed out for remote address: %s", strerror(errno));
            data->responseStatus = SOCKS5_TTL_EXPIRED;
            break;
        default:
        log(ERROR, "Unhandled connect error: %s", strerror(errno));
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Default error code TODO is this right?
            break;
    }
}

int setupTCPRemoteSocket(const struct destination_info *destination,  struct selector_key * key) {
    clientData *data = key->data; // Get the client data from the key
    int remoteSock = -1;
    // Connect to the remote address
    struct sockaddr_storage remoteAddr = {0};
    socklen_t addrLen = 0;

    if (destination->addressType == IPV4) {
         remoteSock = socket( AF_INET, SOCK_STREAM, 0);
        if (remoteSock < 0) {
            log(ERROR, "socket() failed: %s", strerror(errno));
            data->responseStatus = SOCKS5_GENERAL_FAILURE;
            return -1;
        }
        data->remoteSocket = remoteSock; // Store the remote socket in client data

        // Set the socket to non-blocking mode
        if (selector_fd_set_nio(remoteSock) < 0) {
            log(ERROR, "Failed to set remote socket to non-blocking mode: %s", strerror(errno));
            data->responseStatus = SOCKS5_GENERAL_FAILURE;
            return -1;
        }
        struct sockaddr_in *addr = (struct sockaddr_in *) &remoteAddr;
        addr->sin_family = AF_INET;
        addr->sin_port = htons(destination->port);
        addr->sin_addr.s_addr = htonl(destination->address.ipv4);
        addrLen = sizeof(struct sockaddr_in);
    } else if (destination->addressType == IPV6) {
        remoteSock = socket( AF_INET6, SOCK_STREAM, 0);
        if (remoteSock < 0) {
            log(ERROR, "socket() failed: %s", strerror(errno));
            data->responseStatus = SOCKS5_GENERAL_FAILURE;
            return -1;
        }

        // Set the socket to non-blocking mode
        if (selector_fd_set_nio(remoteSock) < 0) {
            log(ERROR, "Failed to set remote socket to non-blocking mode: %s", strerror(errno));
            data->responseStatus = SOCKS5_GENERAL_FAILURE;
            return -1;
        }
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &remoteAddr;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(destination->port);
        memcpy(&addr->sin6_addr, &destination->address.ipv6, sizeof(struct in6_addr));
        addrLen = sizeof(struct sockaddr_in6);
    } else if (destination->addressType == DOMAINNAME) {
        struct addrinfo hints = {0}, *res;
        hints.ai_family = AF_UNSPEC; // Allow both IPv4 and IPv6
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP; // TCP protocol

        char portStr[8];
        snprintf(portStr, sizeof(portStr), "%d", destination->port);

        const int ret = getaddrinfo(destination->address.domainName, portStr, &hints, &res);
        if (ret != 0) {
            log(ERROR, "getaddrinfo() failed for domain %s: %s", destination->address.domainName, gai_strerror(ret));
            data->responseStatus = SOCKS5_HOST_UNREACHABLE; // TODO is this ok? chatgpt me dijo q si
            return -1;
        }


        for (const struct addrinfo *p = res; p != NULL; p = p->ai_next) {
            // Try to use the address
            if (p->ai_family == AF_INET || p->ai_family == AF_INET6) {
                remoteSock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
                if (remoteSock == -1) {
                    data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
                    continue; // Intentá con la siguiente dirección
                }

                if (selector_fd_set_nio(remoteSock) < 0) {
                    log(ERROR, "Failed to set non-blocking mode: %s", strerror(errno));
                    close(remoteSock); // TODO i should close but if i close them all it will blow up in error_client or done since it tries to close
                    remoteSock = -1;
                    data->responseStatus = SOCKS5_GENERAL_FAILURE;
                    continue;
                }

                if (connect(remoteSock, p->ai_addr, p->ai_addrlen) < 0) {
                    if (errno != EINPROGRESS) { // Non-blocking connect //TODO check related errors
                        log(ERROR, "connect() failed: %s", strerror(errno));
                        close(remoteSock);
                        remoteSock = -1; // Reset remoteSock to indicate failure
                        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
                        continue;
                    }
                    if (remoteSocketInit(remoteSock, key, p->ai_next) < 0 )
                        return -1; // Initialize the remote socket
                    selector_set_interest_key(key, OP_NOOP); // Set interest to write for the remote socket
                }
                // Copy the address to remoteAddr
                if (p->ai_family == AF_INET) {
                    struct sockaddr_in *addr = (struct sockaddr_in *) &remoteAddr;
                    memcpy(addr, p->ai_addr, sizeof(struct sockaddr_in));
                    addrLen = sizeof(struct sockaddr_in);
                } else if (p->ai_family == AF_INET6) {
                    struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &remoteAddr;
                    memcpy(addr, p->ai_addr, sizeof(struct sockaddr_in6));
                    addrLen = sizeof(struct sockaddr_in6);
                }
                // Print the address we are connecting to
                printSocketAddress((struct sockaddr *) &remoteAddr, addrBuffer);
                log(INFO, "Connecting to remote %s", addrBuffer);
                return remoteSock;
            }
        }

        if (addrLen == 0) {
            log(ERROR, "No valid addresses found for domain %s", destination->address.domainName);
            freeaddrinfo(res);
            return -1;
        }

        // Free the address info structure
        freeaddrinfo(res);
    } else {
        log(ERROR, "Unsupported address type: %d", destination->addressType);
        return -1;
    }

    if (destination->addressType != DOMAINNAME && connect(remoteSock, (struct sockaddr *) &remoteAddr, addrLen) < 0) {
        if (errno != EINPROGRESS) { // Non-blocking connect
            log(ERROR, "connect() failed: %s", strerror(errno));
            int error = errno;
            setResponseStatus(data, error); // Set the appropriate response status based on the error
            return -1;
        }
        log(INFO, "connect() in progress for remote address");
        if (remoteSocketInit(remoteSock, key, NULL) < 0 ) {
            log(ERROR, "Failed to initialize remote socket");
            return -1; // Initialize the remote socket
        }
        selector_set_interest_key(key, OP_NOOP); // Set interest to write for the remote socket
        return remoteSock;
    }
    // Print remote address of socket
    printSocketAddress((struct sockaddr *) &remoteAddr, addrBuffer);
    log(INFO, "Connecting to remote %s", addrBuffer);
    return remoteSock;
}


int acceptTCPConnection(int servSock) {
    struct sockaddr_storage clntAddr; // Client address
    // Set length of client address structure (in-out parameter)
    socklen_t clntAddrLen = sizeof(clntAddr);

    // Wait for a client to connect
    int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
    if (clntSock < 0) {
        log(ERROR, "accept() failed");
        return -1;
    }

    // clntSock is connected to a client!
    printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);
    log(INFO, "Handling client %s", addrBuffer);

    return clntSock;
}

unsigned connectWrite(struct selector_key * key) {
    remoteData *data = key->data;

    if (data->connectionReady) {
        log(INFO, "Connection already ready for client socket %d", key->fd);
    } else {
        int error =0;
        socklen_t len = sizeof(error);
        if ( getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            log(ERROR, "getsockopt() failed: %s", strerror(errno));
            data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            selector_set_interest(key->s,data->client_fd, OP_WRITE);
            return RELAY_ERROR; // TODO definir codigos de error
        }

        if (error != 0) { //TODO: revisar pero parece funcionar, deberia cerrar el socket anterior?
            log(ERROR, "Connection error on remote socket %d: %s",key->fd , strerror(error));
            setResponseStatus(data->client, error);

            int newRemoteSocket = -1;

            for (struct addrinfo *addr = data->remoteAddrInfo; addr != NULL; addr = addr->ai_next) { //TODO this for loop could use modularization, repeated code in setupRemoteTCPSocket
                log(INFO, "Trying next address: %s", printAddressPort(addr, addrBuffer));
                newRemoteSocket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
                if (newRemoteSocket < 0) {
                    log(ERROR, "Failed to create socket for address %s: %s", addrBuffer, strerror(errno));
                    data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
                    continue;
                }

                if (selector_fd_set_nio(newRemoteSocket) < 0) {
                    log(ERROR, "Failed to set non-blocking mode for address %s: %s", addrBuffer, strerror(errno));
                    close(newRemoteSocket);
                    newRemoteSocket = -1; // Reset to indicate failure
                    data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
                    continue;
                }

                if (connect(newRemoteSocket, addr->ai_addr, addr->ai_addrlen) < 0) {
                    if (errno != EINPROGRESS) { // Non-blocking connect
                        log(ERROR, "connect() failed for address %s: %s", addrBuffer, strerror(errno));
                        close(newRemoteSocket);
                        newRemoteSocket = -1; // Reset to indicate failure

                        int connectError = errno;
                        setResponseStatus(data->client, connectError); // Set the appropriate response status based on the error

                        continue;
                    }
                }

                // Successfully connected to a new address
                if (remoteSocketInit(newRemoteSocket, key, addr->ai_next) < 0) {
                    log(ERROR, "Failed to initialize remote socket for address %s", addrBuffer);
                    close(newRemoteSocket);
                    newRemoteSocket = -1;
                    data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
                    continue;
                }
                selector_set_interest_key(key, OP_NOOP); // Set interest to write for the remote socket
                return RELAY_CONNECTING; // Change to the connecting state
            }

            selector_set_interest(key->s, data->client_fd, OP_WRITE); // Set interest to write for the client socket
            log(ERROR, "Failed to connect to any remote address for client socket %d", key->fd);
            return RELAY_ERROR;
        }
        log(INFO, "Connection established for client socket %d", key->fd);
        data->connectionReady = 1;
    }

    if (setRemoteAddress(key->fd, data) < 0) {
        log(ERROR, "Failed to set remote address for client socket %d", key->fd);
        selector_set_interest(key->s, data->client_fd, OP_WRITE); // Set interest to write for the client socket
        return RELAY_ERROR; // TODO definir codigos de error
    }

    data->client->responseStatus = SOCKS5_SUCCEEDED; // Set response status to success
    selector_set_interest(key->s,data->client_fd, OP_WRITE);
    selector_set_interest(key->s, key->fd, OP_NOOP);
    return RELAY_REMOTE; // Change to the relay remote state

}
void sendFailureResponse(int clntSocket, char *response) {
    response[3] = IPV4; // Address type (0 for IPv4)
    ssize_t numBytesSent = send(clntSocket, response, 10, MSG_DONTWAIT); // Send the failure response TODO magic number, yay
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
    // Enviar respuesta al cliente
    log(INFO, "Writing response to client socket %d", clntSocket);


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
        log(INFO, "Bound to local IPv4 address: %s:%d", addrStr, ntohs(addr->sin_port));
    } else if (localAddr.ss_family == AF_INET6) {
        // IPv6 address
        const struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&localAddr;
        response[3] = IPV6; // Address type is IPv6
        memcpy(response + 4, &addr->sin6_addr, sizeof(addr->sin6_addr)); // Copy the bound IPv6 address
        memcpy(response + 20, &addr->sin6_port, sizeof(addr->sin6_port)); // Copy the bound port (already in network byte order)

        char addrStr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(addr->sin6_addr), addrStr, sizeof(addrStr));
        log(INFO, "Bound to local IPv6 address: [%s]:%d", addrStr, ntohs(addr->sin6_port));
    } else { //todo this should not be possible, ostrich algorithm ftw
        log(ERROR, "Unsupported address family: %d", localAddr.ss_family);
        return ERROR_CLIENT;
    }

    //send the response to the client
    const ssize_t numBytesSent = send(clntSocket, response, localAddr.ss_family == AF_INET ? 10: 22, MSG_DONTWAIT); //fixme: puede ser esto, mandar largo exacto
    if (numBytesSent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE; // TODO definir codigos de error
    }
    if (numBytesSent < (localAddr.ss_family == AF_INET ? 10: 22) ) { //todo magic numbers, yay
        log(INFO, "Partial send: sent %zd bytes, expected %zu bytes", numBytesSent, sizeof(response));
        return REQUEST_WRITE;
    }
    // Log the number of bytes sent
    log(INFO, "Sent %zd bytes to client socket %d", numBytesSent, clntSocket);
    buffer_reset(data->clientBuffer); // Reset the client buffer for the next request
    selector_set_interest_key(key, OP_READ);
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
    log(INFO, "Received domain name: %s", domainName);
    const uint16_t port = ntohs(*(uint16_t *)data->clientBuffer->read); // Leer el puerto
    log(INFO, "Received port: %d", port);
    buffer_read_adv(data->clientBuffer, 2); // Avanzar el puntero de lectura
    data->destination.addressType = DOMAINNAME; // Guardar el tipo de dirección
    strncpy(data->destination.address.domainName, domainName, sizeof(data->destination.address.domainName) - 1); // Guardar el nombre de dominio
    data->destination.address.domainName[sizeof(data->destination.address.domainName) - 1] = '\0'; // Asegurar que esté terminado en nulo
    data->destination.port = port; // Guardar el puerto

    log(INFO, "Connecting to domain name %s:%d", domainName, port);

    selector_set_interest_key(key, OP_WRITE); // Cambiar el interés a escritura

    buffer_reset(data->clientBuffer); // Resetear el buffer para la siguiente lectura

    if ( setupTCPRemoteSocket(&data->destination, key) < 0) {
        selector_set_interest_key(key, OP_WRITE); //TODO capaz no necesario pero por las dudas
    }

    return REQUEST_WRITE; // Cambiar al estado de escritura de solicitud
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
    log(INFO, "Received IPv4 address: %s", inet_ntoa(*(struct in_addr *)&ip));
    buffer_read_adv(data->clientBuffer, 4);
    readPtr = buffer_read_ptr(data->clientBuffer, &readLimit);
    const uint16_t port = ntohs(*(uint16_t *)readPtr);
    log(INFO, "Received port: %d", port);
    buffer_read_adv(data->clientBuffer, 2);

    data->destination.addressType = IPV4; // Guardar el tipo de dirección
    data->destination.address.ipv4 = ip; // Guardar la dirección IPv4
    data->destination.port = port; // Guardar el puerto

    log(INFO, "Connecting to IPv4 address %s:%d", inet_ntoa(*(struct in_addr *)&ip), port);

    selector_set_interest_key(key, OP_WRITE); // Cambiar el interés a escritura

    buffer_reset(data->clientBuffer); // Resetear el buffer para la siguiente lectura

    if ( setupTCPRemoteSocket(&data->destination, key) < 0) {
        selector_set_interest_key(key, OP_WRITE); //TODO capaz no necesario pero por las dudas
    }

    return REQUEST_WRITE; // Cambiar al estado de escritura de solicitud
}

unsigned handleIPv6RequestRead(struct selector_key *key) {
    clientData *data = key->data;
    size_t readLimit;
    uint8_t *readPtr = buffer_read_ptr(data->clientBuffer, &readLimit);
    if (readLimit < 18) { // 16 bytes de IP + 2 bytes de puerto
        log(ERROR, "Incomplete IPv4 address received");
        return REQUEST_READ; // TODO definir codigos de error
    }
    char ipv6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, data->clientBuffer->read, ipv6, sizeof(ipv6)); // Leer la dirección IPv6
    log(INFO, "Received IPv6 address: %s", ipv6);
    buffer_read_adv(data->clientBuffer, 16); // Avanzar el puntero de lectura
    const uint16_t port = ntohs(*(uint16_t *)data->clientBuffer->read); // Leer el puerto
    log(INFO, "Received port: %d", port);
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

    log(INFO, "Connecting to IPv6 address [%s]:%d", ipv6, port);

    selector_set_interest_key(key, OP_WRITE); // Cambiar el interés a escritura

    buffer_reset(data->clientBuffer); // Resetear el buffer para la siguiente lectura

    if ( setupTCPRemoteSocket(&data->destination, key) < 0) {
        selector_set_interest_key(key, OP_WRITE); //TODO capaz no necesario pero por las dudas
    }

    return REQUEST_WRITE; // Cambiar al estado de escritura de solicitud
}

unsigned handleRequestRead(struct selector_key *key) {
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = key->data;

    // Recibir mensaje del cliente
    log(INFO, "Reading request from client socket %d", clntSocket);
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    buffer_write_adv(data->clientBuffer, numBytesRcvd); // Avanzar el puntero de escritura del buffer
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d", clntSocket);
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE; // TODO definir codigos de error
    }
    log(INFO, "Received %zd bytes from client socket %d", numBytesRcvd, clntSocket);

    data->responseStatus = SOCKS5_SUCCEEDED; // Inicializar el estado de respuesta como éxito

    // Procesar la solicitud del cliente
    const uint8_t socksVersion = buffer_read(data->clientBuffer);
    if (socksVersion != SOCKS_VERSION) {
        log(ERROR, "Unsupported SOCKS version: %d", socksVersion);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set error status
        selector_set_interest_key(key, OP_WRITE); // Set interest to write for the client socket
        return REQUEST_WRITE;
    }
        // Leer el comando de la solicitud
    const uint8_t command = buffer_read(data->clientBuffer);
    if (command != CONNECT) { // Solo soportamos el comando CONNECT (0x01)
        log(ERROR, "Unsupported command: %d", command);
        data->responseStatus = SOCKS5_COMMAND_NOT_SUPPORTED; // Set error status
        selector_set_interest_key(key, OP_WRITE); // Set interest to write for the client socket
        return REQUEST_WRITE;
    }

    const uint8_t rsv = buffer_read(data->clientBuffer); // Reservado, debe ser 0x00
    if (rsv != RSV) {
        log(ERROR, "Invalid RSV field: %d", rsv);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set error status
        selector_set_interest_key(key, OP_WRITE); // Set interest to write for the client socket
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
    selector_set_interest_key(key, OP_WRITE); // Set interest to write for the client socket
    return REQUEST_WRITE;

}



int initializeClientData(clientData *data) {
    struct state_machine *stm = malloc(sizeof(struct state_machine));
    if (stm == NULL) {
        perror("Failed to allocate memory for state machine");
        exit(EXIT_FAILURE);
    }
    stm->initial = HELLO_READ;
    stm->states = states;
    stm->max_state = RELAY_CLIENT; // Total number of states
    stm_init(stm);
	buffer *buf = malloc(sizeof(buffer));
    if (buf == NULL) {
        perror("Failed to allocate memory for buffer");
        free(stm);
        free(data);
        return -1;
    }
    buf->data = malloc(BUFSIZE * sizeof(char)); // Allocate buffer data
    if (buf->data == NULL) {
        perror("Failed to allocate memory for buffer data");
        free(buf);
        free(stm);
        free(data);

        return -1;
    }
    buffer_init(buf, BUFSIZE, buf->data); // Initialize the buffer

    data->clientBuffer = buf;

    data->authMethod = NO_ACCEPTABLE_METHODS; // Error auth method
    data->stm = stm; // Assign the state machine to client data
    return 0;
}
void handleMasterClose(struct selector_key *key) {
    close(key->fd); // Close the master socket
}

void handleMasterRead(struct selector_key *key) {
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    // aceptamos
    const int new_socket = acceptTCPConnection(key->fd);
    if (new_socket < 0) {
        perror("accept");
        return;
    }

    // bloqueo = no
    if (selector_fd_set_nio(new_socket) == -1) {
        close(new_socket);
        perror("Failed to set client socket to non-blocking mode");
        return;
    }

    // loggeo (creo q ni necesario pero queda lindo)
    getpeername(new_socket, (struct sockaddr*)&address, &addrlen);
    printf("New connection, socket fd is %d, ip is: %s, port: %d\n",
           new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

    // Prepare client data structure
    clientData *data = malloc(sizeof(clientData));
     if (data == NULL) {
        log(ERROR, "Failed to allocate memory for client data");
        return ;
    }

    if (initializeClientData(data) < 0) {
        close(new_socket);
        return; // Error initializing client data
    }

    // Registrar con interés inicial
    if (SELECTOR_SUCCESS != selector_register(key->s, new_socket, &client_handler, OP_READ, data)) {
        perror("Failed to register client socket");
        free(data->clientBuffer);
        free(data);
        close(new_socket);
        return;
    }

    printf("Client socket %d registered with selector\n", new_socket);
}

void socks5_relay_close(struct selector_key *key) {
    remoteData *rData = key->data;
    if (rData != NULL) {
        log(INFO, "Closing remote socket %d for client %d", key->fd, rData->client_fd);
        if (rData->buffer != NULL) {
            free(rData->buffer->data); // Free the buffer data
            free(rData->buffer); // Free the buffer
        }
        if (rData->client != NULL) {
            free(rData->client); // Free the client data
        }
        free(rData); // Free the remote data structure
        close(key->fd); // Close the remote socket
    }
}
void socks5_relay_read(struct selector_key *key) {
    const remoteData *rData = key->data;
    if (rData != NULL && rData->stm != NULL) {
        log(INFO, "Reading from remote socket %d for client %d", key->fd, rData->client_fd);
        stm_handler_read(rData->stm, key); // Read data from the remote socket
    }
}

void socks5_relay_write(struct selector_key *key) {
    const remoteData *rData = key->data;
    if (rData != NULL && rData->stm != NULL) {
        log(INFO, "Writing to remote socket %d for client %d", key->fd, rData->client_fd);
        stm_handler_write(rData->stm, key); // Write data to the remote socket
    }
}


void socks5_close(struct selector_key *key) {
    const clientData *data = key->data;
    if (data != NULL) {
      	log(INFO, "Closing client socket %d", key->fd);
        stm_handler_close(data->stm, key);
    }
}

void socks5_read(struct selector_key *key) {
    clientData *data = key->data;
    stm_handler_read(data->stm, key); //usar enum para detectar errores
}

void socks5_write(struct selector_key *key) {
    clientData *data = key->data;
    stm_handler_write(data->stm, key);
}

void socks5_block(struct selector_key *key) {
    clientData *data = key->data;
    stm_handler_block(data->stm, key);
}