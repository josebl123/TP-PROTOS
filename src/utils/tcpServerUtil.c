#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "logger.h"
#include "util.h"
#include "tcpServerUtil.h"

#include "../selector.h"

#define MAXPENDING 5 // Maximum outstanding connection requests
#define MAX_ADDR_BUFFER 128
#define BUFSIZE 1024 // Buffer size for client data

static char addrBuffer[MAX_ADDR_BUFFER];
/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
int setupTCPServerSocket(const char *service) {
    // Construct the server address structure
    struct addrinfo addrCriteria;                   // Criteria for address match
    memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
    addrCriteria.ai_family = AF_UNSPEC;             // Any address family
    addrCriteria.ai_flags = AI_PASSIVE;             // Accept on any address/port
    addrCriteria.ai_socktype = SOCK_STREAM;         // Only stream sockets
    addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

    struct addrinfo *servAddr; 			// List of server addresses
    int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr);
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

void handleClientWrite(struct selector_key *key) {
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = (clientData *) key->data;

    char * initialAddress = data->buffer + data->bufferOffset;

    ssize_t numBytesSent = send(clntSocket, initialAddress, data->bufferSize, MSG_DONTWAIT);
    if (numBytesSent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            return;
        }
        log(ERROR, "send() failed on client socket %d", clntSocket);
        free(data->buffer); // Liberar el buffer
        data->buffer = NULL; // Evitar uso posterior del puntero
        return; // TODO definir codigos de error
    } else if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        free(data->buffer); // Liberar el buffer
        selector_unregister_fd(key->s, clntSocket); // Desregistrar el socket del cliente
        return;
    } else {
        // Mensaje enviado correctamente, desregistrar el interés de escritura
        if (data->bufferSize == numBytesSent) {
            data->bufferOffset = 0; // Reiniciar el offset del buffer
        }
        data->bufferSize -= numBytesSent; // Actualizar el tamaño del buffer
        selector_set_interest_key(key, OP_READ);
    }
}


void handleClientRead(struct selector_key *key) {
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = (clientData *) key->data;
    // Recibir mensaje del cliente
    ssize_t numBytesRcvd = recv(clntSocket, data->buffer + data->bufferOffset, BUFSIZE - data->bufferOffset, 0);
    if (numBytesRcvd < 0) { //TODO en este caso que se hace? Libero todo?
        log(ERROR, "recv() failed on client socket %d", clntSocket);
        return; // TODO definir codigos de error
    }
    else if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        free(data->buffer); // Liberar el buffer
        selector_unregister_fd(key->s, clntSocket); // Desregistrar el socket del cliente
        return;
    } else {
        // Enviar mensaje de vuelta al cliente
        selector_set_interest_key(key, OP_WRITE);
        data->bufferSize += numBytesRcvd; // Guardar el tamaño del buffer
        log(INFO, "Received %zd bytes from client socket %d: %.*s", numBytesRcvd, clntSocket, (int)numBytesRcvd, data->buffer);

    }

}

void handleTCPEchoClientClose(struct selector_key *key) {
    printf("Closing client socket %d\n", key->fd);
    close(key->fd); // Cerrar el socket del cliente
    free(key->data); // Liberar los datos del cliente
}

void handleMasterRead(struct selector_key *key) {
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    char *message = "W\r\n";
    size_t messageLen = strlen(message);

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
        perror("Failed to allocate memory for client data");
        close(new_socket);
        return;
    }

    // Initialize client data and store welcome message
    data->buffer = malloc( BUFSIZE * sizeof(char));
    if (data->buffer == NULL) {
        perror("Failed to allocate memory for welcome message");
        free(data);
        close(new_socket);
        return;
    }

    memcpy(data->buffer, message, messageLen);
    data->bufferSize = messageLen;
    data->bufferOffset = 0;

    // handler de cliente
    fd_handler *client_handler = malloc(sizeof(fd_handler));
    if (client_handler == NULL) {
        perror("Failed to allocate memory for client handler");
        free(data->buffer);
        free(data);
        close(new_socket);
        return;
    }

    // Inicializar el handler de cliente
    client_handler->handle_read = handleClientRead;
    client_handler->handle_write = handleClientWrite;
    client_handler->handle_block = NULL; // No se usa en este caso
    client_handler->handle_close = handleTCPEchoClientClose;

    // Registrar con interés inicial en escritura para enviar mensaje de bienvenida
    if (SELECTOR_SUCCESS != selector_register(key->s, new_socket, client_handler, OP_WRITE, data)) {
        perror("Failed to register client socket");
        free(client_handler);
        free(data->buffer);
        free(data);
        close(new_socket);
        return;
    }

    printf("Client socket %d registered with selector\n", new_socket);
}

