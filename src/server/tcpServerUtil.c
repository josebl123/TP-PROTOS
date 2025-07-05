#define _GNU_SOURCE
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
#include  <signal.h>

#include "../selector.h"
#include "../buffer.h"
#include "../metrics/metrics.h"
#include "../utils/user_metrics_table.h"
#include <time.h>


#define MAXPENDING 15 // Maximum outstanding connection requests TODO i changed this, was 5
#define MAX_ADDR_BUFFER 128
#define BUFSIZE 2048  // Buffer size for client data

//MEGA TODO FIX THE CASING OF THE NAMES, IT IS A MESS (CAMEL CASE AND SNAKE CASE MIXED)

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
    clientData *data =  key->data;
    data->current_user_conn.status = 0; //TODO: NOT MAGIC NUMBERS
    log(INFO, "USER: %s", data->authInfo.username);
    user_metrics * user_metrics = get_or_create_user_metrics(data->authInfo.username);

    char time_str[64];
    struct tm tm_info;
    localtime_r(&data->current_user_conn.access_time, &tm_info);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);

    log(INFO, "Saving user connection IN CLIENT CLOSE: status=%d, bytes_sent=%lu, bytes_received=%lu, port_origin=%u, port_destination=%u, destination_name=%s, access_time=%s",
        data->current_user_conn.status,
        data->current_user_conn.bytes_sent,
        data->current_user_conn.bytes_received,
        data->current_user_conn.port_origin,
        data->current_user_conn.port_destination,
        data->current_user_conn.destination_name ? data->current_user_conn.destination_name : "NULL",
        time_str
    );
    metrics_connection_closed();


    // Suponiendo que tenés el user_metrics del cliente:
    user_metrics_add_connection(user_metrics, &data->current_user_conn);
    selector_unregister_fd(key->s, key->fd); // Desregistrar el socket del selector
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
    [DOMAIN_RESOLVING] = { .state = DOMAIN_RESOLVING, .on_block_ready = handleDomainResolve}, // Resolving domain name
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
    .handle_block = socks5_block, // Block handler for DNS resolution
    .handle_close =  handleTcpClose// Close handler // TODO add state machine on close, might be better because some states complex closing logic (eg. several attempts to connect to remote socket)
};
static const fd_handler relay_handler = {
    .handle_read = socks5_relay_read, // Relay read handler
    .handle_write = socks5_relay_write, // Relay write handler
    .handle_block = NULL, // Not used in this case
    .handle_close = handleRemoteClose // Relay close handler
};


int setupTCPServerSocket(const char *ip, const int port) {
    // Construct the server address structure
    struct addrinfo addrCriteria = {0};                   // Criteria for address match
    addrCriteria.ai_family = AF_UNSPEC;             // Any address family
    // addrCriteria.ai_flags = AI_PASSIVE;             // Accept on any address/port
    addrCriteria.ai_socktype = SOCK_STREAM;         // Only stream sockets
    addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol
    // Convertir el puerto a string
    char portStr[6];   // Máx: 65535 + null
    snprintf(portStr, sizeof(portStr), "%d", port);

    struct addrinfo *servAddr; 			// List of server addresses
    const int rtnVal = getaddrinfo(ip, portStr, &addrCriteria, &servAddr);
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
        close(remoteSocket);
        return -1; // TODO definir codigos de error
    }

    log(INFO, "Remote socket %d initialized and registered with selector for client %d", remoteSocket, key->fd);

    return 0;
}

unsigned handleDomainResolve(struct selector_key *key) {
    clientData *data = key->data; // Get the client data from the key

    if (data->addressResolved) {
        log(INFO, "Address already resolved for client socket %d", key->fd);
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        }
        return REQUEST_WRITE;
    }

    int remoteSocket = -1; // Initialize remote socket

    log(INFO, "Resolving domain name for client socket %d", key->fd);


    for (struct addrinfo *addr = data->remoteAddrInfo; addr != NULL; addr = addr->ai_next) { //TODO this for loop could use modularization, repeated code in setupRemoteTCPSocket
        log(INFO, "Trying next address: %s", printAddressPort(addr, addrBuffer));
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
        if (remoteSocketInit(remoteSocket, key, addr->ai_next) < 0) {
            log(ERROR, "Failed to initialize remote socket for address %s", addrBuffer);
            close(remoteSocket);
            remoteSocket = -1;
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            continue;
        }
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            close(remoteSocket);
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

void getAddrInfoCallBack(union sigval sigval) {
    struct dnsReq *req = sigval.sival_ptr; // Get the request from the signal value
    clientData *data = req->clientData; // Get the client data from the request

    log(INFO, "getAddrInfoCallBack called for request on fd %d", req->fd);


    if (gai_error(&req->request) != 0) {
        log(ERROR, "getaddrinfo() failed: %s", gai_strerror(gai_error(&req->request)));
        if (req->request.ar_result != NULL) {
            freeaddrinfo(req->request.ar_result); // Free the address info structure
        }
        data->responseStatus = SOCKS5_HOST_UNREACHABLE; // Set the response status to host unreachable
        metrics_add_server_error();
        if (selector_notify_block(req->fdSelector, req->fd) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to notify selector for fd %d", req->fd);
        }
        data->addressResolved = 1; // Mark the address as resolved (failed)
        return; // Exit if getaddrinfo failed
    }

    data->addressResolved = 0; // Mark the address as not resolved (success)
    data->remoteAddrInfo = req->request.ar_result; // Store the result in client data
    log(INFO, "getaddrinfo() succeeded for domain %s", req->request.ar_name);

    if (selector_notify_block(req->fdSelector, req->fd) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to notify selector for fd %d", req->fd);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
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
            metrics_add_server_error();
            return -1;
        }
        data->remoteSocket = remoteSock; // Store the remote socket in client data

        // Set the socket to non-blocking mode
        if (selector_fd_set_nio(remoteSock) < 0) {
            log(ERROR, "Failed to set remote socket to non-blocking mode: %s", strerror(errno));
            data->responseStatus = SOCKS5_GENERAL_FAILURE;
            metrics_add_server_error();
            return -1;
        }
        struct sockaddr_in *addr = (struct sockaddr_in *) &remoteAddr;
        addr->sin_family = AF_INET;
        addr->sin_port = htons(destination->port);
        addr->sin_addr.s_addr = htonl(destination->address.ipv4);
        addrLen = sizeof(struct sockaddr_in);
        metrics_add_ipv4_connection();

    } else if (destination->addressType == IPV6) {
        remoteSock = socket( AF_INET6, SOCK_STREAM, 0);
        if (remoteSock < 0) {
            log(ERROR, "socket() failed: %s", strerror(errno));
            data->responseStatus = SOCKS5_GENERAL_FAILURE;
            metrics_add_server_error();
            return -1;
        }

        // Set the socket to non-blocking mode
        if (selector_fd_set_nio(remoteSock) < 0) {
            log(ERROR, "Failed to set remote socket to non-blocking mode: %s", strerror(errno));
            data->responseStatus = SOCKS5_GENERAL_FAILURE;
            metrics_add_server_error();
            return -1;
        }
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &remoteAddr;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(destination->port);
        memcpy(&addr->sin6_addr, &destination->address.ipv6, sizeof(struct in6_addr));
        addrLen = sizeof(struct sockaddr_in6);
        metrics_add_ipv6_connection();
    } else if (destination->addressType == DOMAINNAME) {
        char portStr[8];
        snprintf(portStr, sizeof(portStr), "%d", destination->port);

        struct dnsReq *dnsRequest = data->dnsRequest; // Get the DNS request structure from client data
        snprintf(dnsRequest->port, sizeof(dnsRequest->port), "%d", destination->port);
        memset(&dnsRequest->hints, 0, sizeof(dnsRequest->hints)); // Initialize hints structure

        struct gaicb *request[] = { &dnsRequest->request };
        dnsRequest->request.ar_name = destination->address.domainName; // Set the domain name for the DNS request
        dnsRequest->request.ar_service = portStr; // Set the service (port) for the DNS request
        dnsRequest->hints.ai_protocol = IPPROTO_TCP; // Set the protocol for the DNS request
        dnsRequest->hints.ai_family = AF_UNSPEC; // Allow both IPv4 and IPv6
        dnsRequest->hints.ai_socktype = SOCK_STREAM; // TCP socket type
        dnsRequest->request.ar_request = &dnsRequest->hints; // Set the request pointer
        dnsRequest->request.ar_result = NULL; // Initialize result to NULL
        dnsRequest->clientData = data; // Set the client data for the DNS request
        dnsRequest->fdSelector = key->s; // Set the selector for the DNS request
        dnsRequest->fd = key->fd; // Set the file descriptor for the DNS request

        // Set up signal event for the callback
        struct sigevent sigevent;
        memset(&sigevent, 0, sizeof(sigevent));
        sigevent.sigev_notify = SIGEV_THREAD;  // Use a thread to handle the callback
        sigevent.sigev_notify_function = getAddrInfoCallBack;  // Set the callback function
        sigevent.sigev_value.sival_ptr = dnsRequest;  // Pass the DNS request to the callback

        log(INFO, "Starting DNS resolution for domain %s:%s", destination->address.domainName, portStr);

        // Call getaddrinfo_a asynchronously
        int gaiResult = getaddrinfo_a(GAI_NOWAIT, request, 1, &sigevent);
        if (gaiResult != 0) {
            log(ERROR, "getaddrinfo_a() failed for domain %s: %s",
                destination->address.domainName, gai_strerror(gaiResult));
            data->responseStatus = SOCKS5_HOST_UNREACHABLE;
            metrics_add_dns_resolution_error();
            return -1;
        }

        log(INFO, "DNS request for domain %s initiated", destination->address.domainName);

        // Set the interest to OP_NOOP to wait for the DNS resolution callback
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for DNS request key %d", key->fd);
            data->responseStatus = SOCKS5_GENERAL_FAILURE;
            metrics_add_server_error();
            return -1;
        }

        data->addressResolved = 0; // Indicate that the address is not resolved yet
        return 0; // Return 0 to indicate that the DNS request is in progress

    } else {
        log(ERROR, "Unsupported address type: %d", destination->addressType);
        metrics_add_unsupported_input();
        return -1;
    }

    if (destination->addressType != DOMAINNAME && connect(remoteSock, (struct sockaddr *) &remoteAddr, addrLen) < 0) {
        if (errno != EINPROGRESS) { // Non-blocking connect
            log(ERROR, "connect() failed: %s", strerror(errno));
            int error = errno;
            setResponseStatus(data, error); // Set the appropriate response status based on the error
            metrics_add_server_error(); // TODO: Is this a server error?
            return -1;
        }
        log(INFO, "connect() in progress for remote address");
        if (remoteSocketInit(remoteSock, key, NULL) < 0 ) {
            log(ERROR, "Failed to initialize remote socket");
            return -1; // Initialize the remote socket
        }
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            metrics_add_server_error();
            return -1; // TODO definir codigos de error
        }
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
            if (selector_set_interest(key->s,data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", key->fd);
            }
            return RELAY_ERROR; // TODO definir codigos de error
        }

        if (error != 0) { //TODO: revisar pero parece funcionar, deberia cerrar el socket anterior?
            log(ERROR, "Connection error on remote socket %d: %s",key->fd , strerror(error));
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
            } else {
                if (selector_set_interest(key->s, data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
                    log(ERROR, "Failed to set interest for client socket %d", key->fd);
                }
                data->client->addressResolved = 1; // Indicate that the address is resolved (failed)
                return RELAY_ERROR;
            }
        }
        log(INFO, "Connection established for client socket %d", key->fd);
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
    if (data->client->destination.addressType == DOMAINNAME && selector_notify_block(key->s,data->client_fd) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to notify selector for client socket %d", key->fd);
        data->client->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return RELAY_ERROR; // TODO definir codigos de error
    } else if (data->client->destination.addressType != DOMAINNAME && selector_set_interest(key->s, data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
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
        metrics_add_unsupported_input();
        return ERROR_CLIENT;
    }

    //send the response to the client
    const ssize_t numBytesSent = send(clntSocket, response, localAddr.ss_family == AF_INET ? 10: 22, MSG_DONTWAIT); //fixme: puede ser esto, mandar largo exacto
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
        log(INFO, "Partial send: sent %zd bytes, expected %zu bytes", numBytesSent, sizeof(response));
        return REQUEST_WRITE;
    }
    // Log the number of bytes sent
    log(INFO, "Sent %zd bytes to client socket %d", numBytesSent, clntSocket);
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
    log(INFO, "Received domain name: %s", domainName);
    const uint16_t port = ntohs(*(uint16_t *)data->clientBuffer->read); // Leer el puerto
    log(INFO, "Received port: %d", port);
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

    log(INFO, "Connecting to domain name %s:%d", domainName, port);

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
    log(INFO, "Received IPv4 address: %s", inet_ntoa(*(struct in_addr *)&ip));
    buffer_read_adv(data->clientBuffer, 4);
    readPtr = buffer_read_ptr(data->clientBuffer, &readLimit);
    const uint16_t port = ntohs(*(uint16_t *)readPtr);
    log(INFO, "Received port: %d", port);
    buffer_read_adv(data->clientBuffer, 2);

    data->destination.addressType = IPV4; // Guardar el tipo de dirección
    data->destination.address.ipv4 = ip; // Guardar la dirección IPv4
    data->destination.port = port; // Guardar el puerto
    data->current_user_conn.ip_destination.is_ipv6 = 0;
    data->current_user_conn.ip_destination.addr.ipv4.s_addr = htonl(data->destination.address.ipv4);
    data->current_user_conn.destination_name = NULL;
    data->current_user_conn.port_destination = data->destination.port;

    log(INFO, "Connecting to IPv4 address %s:%d", inet_ntoa(*(struct in_addr *)&ip), port);

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

    data->addressResolved = 1; // Indicate that the address is resolved

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
    data->current_user_conn.ip_destination.is_ipv6 = 1;
    data->current_user_conn.ip_destination.addr.ipv6 = data->destination.address.ipv6;
    data->current_user_conn.destination_name = NULL;
    data->current_user_conn.port_destination = data->destination.port;


    log(INFO, "Connecting to IPv6 address [%s]:%d", ipv6, port);

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

    data->addressResolved = 1; // Indicate that the address is resolved

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
        metrics_add_receive_error();
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



int initializeClientData(clientData *data) {
    struct state_machine *stm = malloc(sizeof(struct state_machine));
    if (stm == NULL) {
        perror("Failed to allocate memory for state machine");
        exit(EXIT_FAILURE);
    }
    stm->initial = HELLO_READ;
    stm->states = states;
    stm->max_state = DOMAIN_RESOLVING; // Total number of states
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

    struct dnsReq *dnsRequest = malloc(sizeof(struct dnsReq));
    if (dnsRequest == NULL) {
        perror("Failed to allocate memory for DNS request");
        free(buf->data);
        free(buf);
        free(stm);
        free(data);
        return -1;
    }
    data->dnsRequest = dnsRequest; // Initialize the DNS request structure

    data->authMethod = NO_ACCEPTABLE_METHODS; // Error auth method
    data->stm = stm; // Assign the state machine to client data
    user_connection_init(&data->current_user_conn);
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

    // Set origin info
    if (address.sin_family == AF_INET) {
        data->origin.addressType = IPV4;
        data->origin.address.ipv4 = address.sin_addr.s_addr;
        data->origin.port = ntohs(address.sin_port);
    } else {
        log(ERROR, "Unsupported address family");
    }


    // Registrar con interés inicial
    if (SELECTOR_SUCCESS != selector_register(key->s, new_socket, &client_handler, OP_READ, data)) {
        log(ERROR, "Failed to register client socket %d with selector in master read", new_socket);
        free(data->clientBuffer);
        free(data);
        close(new_socket);
        return;
    }
    metrics_new_connection(); // Update metrics for new connection
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
        stm_handler_read(rData->stm, key); // Read data from the remote socket
    }
}

void socks5_relay_write(struct selector_key *key) {
    const remoteData *rData = key->data;
    if (rData != NULL && rData->stm != NULL) {
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
    log(INFO, "Blocking client socket %d", key->fd);
    stm_handler_block(data->stm, key);
}