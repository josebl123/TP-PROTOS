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

#include "../selector.h"
#include "../buffer.h"


#define MAXPENDING 5 // Maximum outstanding connection requests
#define MAX_ADDR_BUFFER 128
#define BUFSIZE 1024 // Buffer size for client data


#define CONNECT 1
#define RSV 0



static char addrBuffer[MAX_ADDR_BUFFER];
/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
void handleTcpClose(const unsigned state,  struct selector_key *key) {
    int clntSocket = key->fd; // Socket del cliente
    clientData *data =  key->data;
    selector_unregister_fd(key->s, clntSocket); // Desregistrar el socket del cliente
    if (state == ERROR_CLIENT) {
        log(ERROR, "Closing client socket %d due to error", clntSocket);
    } else {
        log(INFO, "Closing client socket %d after completion", clntSocket);
    }
    free(data->buffer->data);
    free(data->buffer);
    free(data);
}

 static const struct state_definition states[] = {
    [HELLO_READ] =    { .state = HELLO_READ, .on_read_ready = handleHelloRead },
    [HELLO_WRITE] =   { .state = HELLO_WRITE, .on_write_ready = handleHelloWrite },
    [AUTH_READ] =     { .state = AUTH_READ, .on_read_ready = handleAuthRead },
    [AUTH_WRITE] =    { .state = AUTH_WRITE, .on_write_ready = handleAuthWrite },
    [REQUEST_READ] =  { .state = REQUEST_READ, .on_read_ready = handleRequestRead },
    [REQUEST_WRITE] = { .state = REQUEST_WRITE, .on_write_ready = handleRequestWrite },
    [DONE] =          { .state = DONE, .on_arrival = handleTcpClose },
    [ERROR_CLIENT] =  { .state = ERROR_CLIENT,.on_arrival = handleTcpClose},
};

 static const fd_handler client_handler = {
    .handle_read = socks5_read, // Initial read handler
    .handle_write = socks5_write, // Initial write handler
    .handle_block = NULL, // Not used in this case
    .handle_close = NULL // Close handler
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
    for (struct addrinfo *addr = servAddr; addr != NULL && servSock == -1; addr = addr->ai_next) {
        errno = 0;
        // Create a TCP socket
        servSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (servSock < 0) {
            log(DEBUG, "Cant't create socket on %s : %s ", printAddressPort(addr, addrBuffer), strerror(errno));
            continue;       // Socket creation failed; try next address
        }

       setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)); // Allow reuse of address

        // Bind to ALL the address and set socket to listen
        if ((bind(servSock, addr->ai_addr, addr->ai_addrlen) == 0) && (listen(servSock, MAXPENDING) == 0)) {
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

unsigned handleRequestWrite(struct selector_key *key) {
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = (clientData *) key->data;
    // Enviar respuesta al cliente
    log(INFO, "Writing response to client socket %d", clntSocket);

    uint8_t response[30]; // Buffer para la respuesta
    response[0] = SOCKS_VERSION; // Versión del protocolo SOCKS
    response[1] = 0x00; // Respuesta OK (no error)
    response[2] = RSV; // Reservado, debe ser 0x00
    response[3] = data->destination.addressType; // Tipo de dirección (IPv4, IPv6 o dominio)
    if (data->destination.addressType == IPV4) {
        // Dirección IPv4
        struct in_addr ipv4Addr;
        ipv4Addr.s_addr = htonl(data->destination.address.ipv4);
        memcpy(response + 4, &ipv4Addr, sizeof(ipv4Addr)); // Copiar la dirección IPv4
        log(INFO, "Connecting to IPv4 address: %s", inet_ntoa(ipv4Addr));
        uint16_t port = htons(data->destination.port); // Convertir el puerto a big-endian
        memcpy(response + 8, &port, sizeof(port)); // Copiar el puerto
        log(INFO, "Connecting to port: %d", data->destination.port);
    } else if (data->destination.addressType == DOMAINNAME) {
        // Nombre de dominio
        size_t domainLength = strlen(data->destination.address.domainName);
        response[4] = (char) domainLength; // Longitud del nombre de dominio
        memcpy(response + 5, data->destination.address.domainName, domainLength); // Copiar el nombre de dominio
        log(INFO, "Connecting to domain name: %s", data->destination.address.domainName);
        uint16_t port = htons(data->destination.port); // Convertir el puerto a big-endian
        memcpy(response + 5 + domainLength, &port, sizeof(port)); // Copiar el puerto
        log(INFO, "Connecting to port: %d", data->destination.port);
    } else if (data->destination.addressType == IPV6) {
        // Dirección IPv6
        struct in6_addr ipv6Addr;
        memcpy(&ipv6Addr, &data->destination.address.ipv6, sizeof(ipv6Addr)); // Copiar la dirección IPv6
        memcpy(response + 4, &ipv6Addr, sizeof(ipv6Addr)); // Copiar la dirección IPv6
        log(INFO, "Connecting to IPv6 address: %s", inet_ntop(AF_INET6, &ipv6Addr, addrBuffer, sizeof(addrBuffer)));
        uint16_t port = htons(data->destination.port); // Convertir el puerto a big-endian
        memcpy(response + 20, &port, sizeof(port)); // Copiar el puerto
        log(INFO, "Connecting to port: %d", data->destination.port);
    } else {
        log(ERROR, "Unsupported address type: %d", data->destination.addressType);
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    //send the response to the client
    ssize_t numBytesSent = send(clntSocket, response, sizeof(response), MSG_DONTWAIT);
    if (numBytesSent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE; // TODO definir codigos de error
    }
    if ((size_t)numBytesSent < sizeof(response)) {
        log(INFO, "Partial send: sent %zd bytes, expected %zu bytes", numBytesSent, sizeof(response));
        return REQUEST_WRITE;
    }
    // Log the number of bytes sent
    log(INFO, "Sent %zd bytes to client socket %d", numBytesSent, clntSocket);

    selector_set_interest_key(key, OP_READ); // Cambiar el interés a lectura
    buffer_reset(data->buffer); // Resetear el buffer para la siguiente lectura
    return REQUEST_READ; //TODO: ESTA MALLLL FIXME Cambiar al estado de lectura de solicitud


}


unsigned handleRequestRead(struct selector_key *key) {
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = (clientData *) key->data;

    // Recibir mensaje del cliente
    log(INFO, "Reading request from client socket %d", clntSocket);
    size_t writeLimit;
    uint8_t *readPtr = buffer_write_ptr(data->buffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, readPtr, writeLimit, 0);
    buffer_write_adv(data->buffer, numBytesRcvd); // Avanzar el puntero de escritura del buffer
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d", clntSocket);
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }
    log(INFO, "Received %zd bytes from client socket %d", numBytesRcvd, clntSocket);
    // Procesar la solicitud del cliente
    const uint8_t socksVersion = buffer_read(data->buffer);
    if (socksVersion != SOCKS_VERSION) {
        log(ERROR, "Unsupported SOCKS version: %d", socksVersion);
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    // Leer el comando de la solicitud
    const uint8_t command = buffer_read(data->buffer);
    if (command != CONNECT) { // Solo soportamos el comando CONNECT (0x01)
        log(ERROR, "Unsupported command: %d", command);
        return ERROR_CLIENT; // TODO definir codigos de error
    }

    const uint8_t rsv = buffer_read(data->buffer); // Reservado, debe ser 0x00
    if (rsv != RSV) {
        log(ERROR, "Invalid RSV field: %d", rsv);
        return ERROR_CLIENT; // TODO definir codigos de error
    }

        // Leer el tipo de dirección
    const uint8_t atyp = buffer_read(data->buffer);
    if (atyp == IPV4) { // Dirección IPv4
        size_t readLimit;
        readPtr = buffer_read_ptr(data->buffer, &readLimit);
        if (readLimit < 6) { // 4 bytes de IP + 2 bytes de puerto
            log(ERROR, "Incomplete IPv4 address received");
            return REQUEST_READ; // TODO definir codigos de error
        }
        uint32_t ip = ntohl(*(uint32_t *)readPtr); // Leer la dirección IP
        log(INFO, "Received IPv4 address: %s", inet_ntoa(*(struct in_addr *)&ip));
        buffer_read_adv(data->buffer, 4); // Avanzar el puntero de lectura
        const uint16_t port = ntohs(*(uint16_t *)readPtr); // Leer el puerto
        log(INFO, "Received port: %d", port);
        buffer_read_adv(data->buffer, 2); // Avanzar el puntero de lectura

        data->destination.addressType = IPV4; // Guardar el tipo de dirección
        data->destination.address.ipv4 = ip; // Guardar la dirección IPv4
        data->destination.port = port; // Guardar el puerto

        log(INFO, "Connecting to IPv4 address %s:%d", inet_ntoa(*(struct in_addr *)&ip), port);

        selector_set_interest_key(key, OP_WRITE); // Cambiar el interés a escritura

        buffer_reset(data->buffer); // Resetear el buffer para la siguiente lectura

        return REQUEST_WRITE; // Cambiar al estado de escritura de solicitud

    }
    if (atyp == DOMAINNAME) { // Nombre de dominio
        const ssize_t domainLength = buffer_read(data->buffer); // Longitud del nombre de dominio
        if (data->buffer->write - data->buffer->read < domainLength + 2) { // Longitud del dominio + 2 bytes de puerto
            log(ERROR, "Incomplete domain name received");
            return REQUEST_READ; // TODO definir codigos de error
        }
        char domainName[domainLength + 1];
        strncpy(domainName, (char *)data->buffer->read, domainLength);
        domainName[domainLength] = '\0';
        buffer_read_adv(data->buffer, domainLength);
        log(INFO, "Received domain name: %s", domainName);
        const uint16_t port = ntohs(*(uint16_t *)data->buffer->read); // Leer el puerto
        log(INFO, "Received port: %d", port);
        buffer_read_adv(data->buffer, 2);

        data->destination.addressType = DOMAINNAME; // Guardar el tipo de dirección
        strncpy(data->destination.address.domainName, domainName, sizeof(data->destination.address.domainName) - 1); // Guardar el nombre de dominio
        data->destination.address.domainName[sizeof(data->destination.address.domainName) - 1] = '\0'; // Asegurar que esté terminado en nulo
        data->destination.port = port; // Guardar el puerto

        log(INFO, "Connecting to domain name %s:%d", domainName, port);

        selector_set_interest_key(key, OP_WRITE);

        buffer_reset(data->buffer);

        return REQUEST_WRITE;
    }
    if (atyp == IPV6) {
        size_t readLimit;
        readPtr = buffer_read_ptr(data->buffer, &readLimit);
        if (readLimit < 18) { // 16 bytes de IP + 2 bytes de puerto
            log(ERROR, "Incomplete IPv4 address received");
            return REQUEST_READ; // TODO definir codigos de error
        }
        char ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, readPtr, ipv6, sizeof(ipv6)); // Leer la dirección IPv6
        log(INFO, "Received IPv6 address: %s", ipv6);
        buffer_read_adv(data->buffer, 16); // Avanzar el puntero de lectura
        const uint16_t port = ntohs(*(uint16_t *)readPtr);
        log(INFO, "Received port: %d", port);
        buffer_read_adv(data->buffer, 2);

        data->destination.addressType = IPV6; // Guardar el tipo de dirección
        inet_pton(AF_INET6, ipv6, &data->destination.address.ipv6); // Guardar la dirección IPv6 TODO check but i think converts fine (string to number)
        data->destination.port = port; // Guardar el puerto

        log(INFO, "Connecting to IPv6 address [%s]:%d", ipv6, port);

        selector_set_interest_key(key, OP_WRITE);

        buffer_reset(data->buffer);
        return REQUEST_WRITE;

    }
    log(ERROR, "Unsupported address type: %d", atyp);
    return ERROR_CLIENT; // TODO definir codigos de error
}



int initializeClientData(clientData *data) {
    struct state_machine *stm = malloc(sizeof(struct state_machine));
    if (stm == NULL) {
        perror("Failed to allocate memory for state machine");
        exit(EXIT_FAILURE);
    }
    stm->initial = HELLO_READ;
    stm->states = states;
    stm->max_state = ERROR_CLIENT; // Total number of states
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

    data->buffer = buf;

    data->bufferSize = BUFSIZE;
    data->bufferOffset = 0;
    data->authMethod = NO_ACCEPTABLE_METHODS; // Error auth method
    data->stm = stm; // Assign the state machine to client data
    return 0;
}

void handleMasterRead(struct selector_key *key) {
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    // aceptamos
    int new_socket = acceptTCPConnection(key->fd);
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

    // Registrar con interés inicial en escritura para enviar mensaje de bienvenida
    if (SELECTOR_SUCCESS != selector_register(key->s, new_socket, &client_handler, OP_READ, data)) {
        perror("Failed to register client socket");
        free(data->buffer);
        free(data);
        close(new_socket);
        return;
    }

    printf("Client socket %d registered with selector\n", new_socket);
}


void socks5_close(struct selector_key *key) {
    clientData *data = key->data;
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