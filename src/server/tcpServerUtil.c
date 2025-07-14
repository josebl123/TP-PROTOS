#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include  <signal.h>
#include "../utils/logger.h"
#include "../utils/util.h"
#include "tcpServerUtil.h"

#include "args.h"
#include "socksAuth.h"
#include "socksRelay.h"
#include "server/server.h"
#include "socksRequest.h"

#include "../selector.h"
#include "../buffer.h"
#include "../metrics/metrics.h"
#include "../utils/user_metrics_table.h"


#define MAXPENDING 15 // Maximum outstanding connection requests TODO i changed this, was 5
#define TIMEOUT_INCOMPLETE_MSG_SEC (60 * 2)

static char addrBuffer[MAX_ADDR_BUFFER];

//MEGA TODO FIX THE CASING OF THE NAMES, IT IS A MESS (CAMEL CASE AND SNAKE CASE MIXED)

void socks5_relay_read(struct selector_key *key);
void socks5_relay_write(struct selector_key *key);

/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
void handleTcpClose(  struct selector_key *key) {
    log(INFO, "TCP Closing client socket %d", key->fd);
    clientData *data =  key->data;

    selector_unregister_fd( key->s,data->remoteSocket); // Desregistrar el socket remoto

    free(data->clientBuffer->data);
    free(data->clientBuffer);
    if (data->remoteBuffer) {
        free(data->remoteBuffer->data);
        free(data->remoteBuffer);
    }
    if (data->pointerToFree) {
        freeaddrinfo(data->pointerToFree); // Liberar la estructura de direcciones remotas
    }
    user_metrics * user_metric = get_or_create_user_metrics(data->authInfo.username);

    char time_str[64];
    struct tm tm_info;
    localtime_r(&data->current_user_conn.access_time, &tm_info);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);
    if (data->responseStatus != SOCKS5_SUCCEEDED) {
        data->current_user_conn.status = SOCKS5_GENERAL_FAILURE; //TODO: MORE DEFINITION OF ERROR CODES
    }
    else {
        data->current_user_conn.status = SOCKS5_SUCCEEDED;
    }
    metrics_connection_closed();

    data->current_user_conn.port_origin = data->origin.port;
    fill_ip_address_from_origin(&data->current_user_conn.ip_origin, &data->origin);

    if (!data->isAnonymous ) {
        user_metrics_add_connection(user_metric, &data->current_user_conn);
    }
    else if (socksArgs->serverAcceptsNoAuth) {
        user_metrics * user_metrics = get_or_create_user_metrics(ANONYMOUS_USER);
        user_metrics_add_connection(user_metrics, &data->current_user_conn);
    }

    free(data->dnsRequest);
    free(data->stm);
    free(data->remote_stm);
    free(data);
    // Close the client socket
    close(key->fd);
}
void handleRemoteClose( struct selector_key *key) {
    log(INFO, "Closing remote socket %d", key->fd);
    close(key->fd);
}
void clientClose(const unsigned state, struct selector_key *key) {
    if (state == ERROR_CLIENT) {
        log(ERROR, "Closing socket %d due to error", key->fd);
    } else {
        log(INFO, "Closing socket %d after completion", key->fd);
    }

    selector_unregister_fd(key->s, key->fd); // Desregistrar el socket del selector
}


void remoteClose(const unsigned state, struct selector_key *key) {
    clientData *data =  key->data;
    if (state == RELAY_ERROR) {
        log(ERROR, "Closing remote socket %d due to error", key->fd);
    } else {
        log(INFO, "Closing remote socket %d after completion", key->fd);
    }
    selector_unregister_fd(key->s, data->clientSocket);
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
    [FAILURE_RESPONSE] = { .state = FAILURE_RESPONSE, .on_write_ready = sendFailureResponseClient }, // Write failure response to client
    [RELAY_CLIENT] = { .state = RELAY_CLIENT, .on_read_ready = handleRelayClientRead,.on_write_ready = handleRelayClientWrite  },
};

static const struct state_definition relay_states[] = {
    [RELAY_CONNECTING] = { .state = RELAY_CONNECTING, .on_write_ready =  connectWrite}, // This state handles the connection to the remote server
    [RELAY_REMOTE] = { .state = RELAY_REMOTE, .on_read_ready = handleRelayRemoteRead, .on_write_ready = handleRelayRemoteWrite },
    [FAILURE_RESPONSE] = { .state = FAILURE_RESPONSE, .on_write_ready = sendFailureResponseRemote }, // Write failure response to remote
    [RELAY_DONE] = { .state = RELAY_DONE, .on_arrival = remoteClose },
    [RELAY_ERROR] = { .state = RELAY_ERROR, .on_arrival = remoteClose },
};

static const fd_handler client_handler = {
    .handle_read = socks5_read, // Initial read handler
    .handle_write = socks5_write, // Initial write handler
    .handle_block = socks5_block, // Block handler for DNS resolution
    .handle_close =  handleTcpClose,
    .handle_timeout = socks5_timeout,
};
static const fd_handler relay_handler = {
    .handle_read = socks5_relay_read, // Relay read handler
    .handle_write = socks5_relay_write, // Relay write handler
    .handle_block = NULL, // Not used in this case
    .handle_close = handleRemoteClose, // Relay close handler
    .handle_timeout = NULL // No timeout handling for relay
};


int setupTCPServerSocket(const char *ip, const int port) {
    // Construct the server address structure
    struct addrinfo addrCriteria = {0};                   // Criteria for address match
    addrCriteria.ai_family = AF_UNSPEC;             // Any address family
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
struct state_machine * createRemoteStateMachine(int initial_state) {
    struct state_machine *stm = malloc(sizeof(struct state_machine));
    if (stm == NULL) {
        log(ERROR, "Failed to allocate memory for remote state machine");
        return NULL;
    }
    stm->initial = initial_state; // Initial state for remote relay
    stm->states = relay_states; // Use the relay states defined above
    stm->max_state = RELAY_ERROR; // Total number of states in the relay machine
    stm_init(stm);
    return stm;
}
int remoteSocketInit(const int remoteSocket, const struct selector_key *key, int initial_state, int intertest) {
    clientData *data = key->data;

    buffer *remoteBuffer = malloc(sizeof(buffer)); // Create a buffer for the remote socket
    if (remoteBuffer == NULL) {
        log(ERROR, "Failed to allocate memory for remote buffer");
        data->responseStatus = SOCKS5_GENERAL_FAILURE;
        return -1;
    }
    remoteBuffer->data = malloc(bufferSize); // Allocate memory for the buffer data
    if (remoteBuffer->data == NULL) {
        log(ERROR, "Failed to allocate memory for remote buffer data");
        data->responseStatus = SOCKS5_GENERAL_FAILURE;
        return -1;
    }
    buffer_init(remoteBuffer, bufferSize, remoteBuffer->data); // Initialize the buffer with a size

    data->remoteBuffer = remoteBuffer; // Set the buffer for the remote socket
    data->remote_stm = createRemoteStateMachine(initial_state); // Create the state machine for the remote socket
    data->remoteSocket = remoteSocket; // Store the remote socket in client data
    data->clientSocket = key->fd; // Store the client socket in client data

    // Register the remote socket with the selector
    if (selector_register(key->s, remoteSocket, &relay_handler, intertest, data) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to register remote socket %d with selector", remoteSocket);
        data->responseStatus = SOCKS5_GENERAL_FAILURE;
        close(remoteSocket);
        return -1;
    }

    return 0;
}


void setResponseStatus(clientData *data, int error) {
    switch (error) {
        case EACCES:
            data->responseStatus = SOCKS5_CONNECTION_NOT_ALLOWED;
            break;
        case ENETUNREACH:
            data->responseStatus = SOCKS5_NETWORK_UNREACHABLE;
            break;
        case EHOSTDOWN:
        case EHOSTUNREACH:
            data->responseStatus = SOCKS5_HOST_UNREACHABLE;
            break;
        case ECONNREFUSED:
            data->responseStatus = SOCKS5_CONNECTION_REFUSED;
            break;
        case ETIMEDOUT:
            data->responseStatus = SOCKS5_TTL_EXPIRED;
            break;
        default:
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Default error code
            break;
    }
}

void getAddrInfoCallBack(union sigval sigval) {
    struct dnsReq *req = sigval.sival_ptr; // Get the request from the signal value
    clientData *data = req->clientData; // Get the client data from the request


    if (gai_error(&req->request) != 0) {
        log(ERROR, "getaddrinfo() failed: %s", gai_strerror(gai_error(&req->request)));
        if (req->request.ar_result != NULL) {
            freeaddrinfo(req->request.ar_result); // Free the address info structure
        }
        data->responseStatus = SOCKS5_HOST_UNREACHABLE; // Set the response status to host unreachable
        metrics_add_server_error();
        data->addressResolved = 1; // Mark the address as resolved (failed)
        if (selector_notify_block(req->fdSelector, req->fd) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to notify selector for fd %d", req->fd);
        }
        return; // Exit if getaddrinfo failed
    }

    data->addressResolved = 0; // Mark the address as not resolved (success)
    data->remoteAddrInfo = req->request.ar_result; // Store the result in client data
    data->pointerToFree = req->request.ar_result; // Store the pointer to free later

    if (selector_notify_block(req->fdSelector, req->fd) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to notify selector for fd %d", req->fd);
        data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
    }
}


int setupTCPRemoteSocket(const struct destinationInfo *destination,  struct selector_key * key) {
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

        // Call getaddrinfo_a asynchronously
        int gaiResult = getaddrinfo_a(GAI_NOWAIT, request, 1, &sigevent);
        if (gaiResult != 0) {
            log(ERROR, "getaddrinfo_a() failed for domain %s: %s",
                destination->address.domainName, gai_strerror(gaiResult));
            data->responseStatus = SOCKS5_HOST_UNREACHABLE;
            metrics_add_dns_resolution_error();
            return -1;
        }

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

    int connected = connect(remoteSock, (struct sockaddr *) &remoteAddr, addrLen);
    if (connected < 0 && errno != EINPROGRESS) {
        log(ERROR, "connect() failed: %s", strerror(errno));
        int error = errno;
        setResponseStatus(data, error); // Set the appropriate response status based on the error
        metrics_add_server_error(); // TODO: Is this a server error?
        return -1;
    }

    if (!connected) {
        log(INFO, "CONNECTED IMMEDIATELY");
        if (remoteSocketInit(remoteSock, key, RELAY_REMOTE, OP_NOOP) < 0 ) {
            log(ERROR, "Failed to initialize remote socket");
            return -1; // Initialize the remote socket
        }
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            metrics_add_server_error();
            return -1;
        }
        data->addressResolved = 1; // Indicate that the address is resolved (success)
    } else {
        if (remoteSocketInit(remoteSock, key, RELAY_CONNECTING, OP_WRITE) < 0 ) {
            log(ERROR, "Failed to initialize remote socket");
            return -1; // Initialize the remote socket
        }
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            data->responseStatus = SOCKS5_GENERAL_FAILURE; // Set general failure status
            metrics_add_server_error();
            return -1;
        }
    }
    // Print remote address of socket
    printSocketAddress((struct sockaddr *) &remoteAddr, addrBuffer);
    return remoteSock;
}

int acceptTCPConnection(int servSock) {
    struct sockaddr_storage clntAddr; // Client address
    // Set length of client address structure (in-out parameter)
    socklen_t clntAddrLen = sizeof(clntAddr);

    // Wait for a client to connect
    const int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
    if (clntSock < 0) {
        log(ERROR, "accept() failed");
        return -1;
    }

    // clntSock is connected to a client!
    printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);

    return clntSock;
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
    buf->data = malloc(bufferSize * sizeof(char)); // Allocate buffer data
    if (buf->data == NULL) {
        perror("Failed to allocate memory for buffer data");
        free(buf);
        free(stm);
        free(data);

        return -1;
    }
    buffer_init(buf, bufferSize, buf->data); // Initialize the buffer

    data->clientBuffer = buf;
    data->remoteBuffer = NULL; // Initialize remote buffer to NULL

    struct dnsReq *dnsRequest = malloc(sizeof(struct dnsReq));
    if (dnsRequest == NULL) {
        perror("Failed to allocate memory for DNS request");
        free(buf->data);
        free(buf);
        free(stm);
        free(data);
        return -1;
    }
    memset(dnsRequest, 0, sizeof(struct dnsReq)); // Initialize DNS request structure
    data->dnsRequest = dnsRequest; // Initialize the DNS request structure
    data->pointerToFree = NULL; // Initialize remote address info to NULL

    data->addressResolved = 0; // Initialize address resolved flag to false

    data->authMethod = NO_ACCEPTABLE_METHODS; // Error auth method
    data->stm = stm; // Assign the state machine to client data
    data->isAnonymous = 1; // Initialize anonymous flag to true
    memset(&data->current_user_conn, 0, sizeof(data->current_user_conn)); // Initialize current user connection data
    user_connection_init(&data->current_user_conn);
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);
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
        log(ERROR, "Failed to accept new connection");
        return;
    }

    // bloqueo = no
    if (selector_fd_set_nio(new_socket) == -1) {
        log(ERROR, "Failed to set non-blocking mode for new socket %d", new_socket);
        close(new_socket);
        return;
    }

    getpeername(new_socket, (struct sockaddr*)&address, &addrlen);

    // Prepare client data structure
    clientData *data = calloc(1, sizeof(clientData));
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
    } else if (address.sin_family == AF_INET6) {
        data->origin.addressType = IPV6;
        const struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&address;
        memcpy(&data->origin.address.ipv6, &addr6->sin6_addr, sizeof(struct in6_addr));
        data->origin.port = ntohs(addr6->sin6_port);
    } else {
        log(ERROR, "Unsupported address family");
    }

    log(INFO, "Accepted new connection from:%d", data->origin.port);


    // Registrar con interés inicial
    if (SELECTOR_SUCCESS != selector_register(key->s, new_socket, &client_handler, OP_READ, data)) {
        log(ERROR, "Failed to register client socket %d with selector in master read", new_socket);
        free(data->clientBuffer);
        free(data);
        close(new_socket);
        return;
    }
}

void socks5_relay_read(struct selector_key *key) {
    const clientData *data = key->data;
    if (data != NULL && data->remote_stm != NULL) {
        stm_handler_read(data->remote_stm, key); // Read data from the remote socket
    }
}

void socks5_relay_write(struct selector_key *key) {
    const clientData *data = key->data;
    if (data != NULL && data->remote_stm != NULL) {
        stm_handler_write(data->remote_stm, key); // Write data to the remote socket
    }
}

void socks5_close(struct selector_key *key) {
    const clientData *data = key->data;
    if (data != NULL) {
        stm_handler_close(data->stm, key);
    }
}

void socks5_read(struct selector_key *key) {
    clientData *data = key->data;
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);
    stm_handler_read(data->stm, key); //usar enum para detectar errores
}

void socks5_write(struct selector_key *key) {
    clientData *data = key->data;
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);
    stm_handler_write(data->stm, key);
}

void socks5_block(struct selector_key *key) {
    clientData *data = key->data;
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);
    stm_handler_block(data->stm, key);
}

void socks5_timeout(struct selector_key *key) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    clientData *clientData =key->data;
    const unsigned currentState = stm_state(clientData->stm);
    fd_interest interest;
    if (selector_get_interest(key->s,key->fd, &interest) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to get interest for key %d", key->fd);
        return;
    }
    if ( currentState == DOMAIN_RESOLVING || interest == OP_NOOP) {
        return;
    }

    if (difftime(now.tv_sec, clientData->last_activity.tv_sec) > TIMEOUT_INCOMPLETE_MSG_SEC) {
        selector_unregister_fd(key->s, key->fd);
    }
}
