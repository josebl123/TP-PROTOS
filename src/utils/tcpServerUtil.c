#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "logger.h"
#include "util.h"

#include "../selector.h"

#define MAXPENDING 5 // Maximum outstanding connection requests
#define BUFSIZE 1024 // Size of receive buffer
#define MAX_ADDR_BUFFER 128

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

int handleTCPEchoClient(int clntSocket) {
    char buffer[BUFSIZE]; // Buffer for echo string
    // Receive message from client
    ssize_t numBytesRcvd = recv(clntSocket, buffer, BUFSIZE, 0);
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed");
        return -1;   // TODO definir codigos de error
    }

    // Send received string and receive again until end of stream
    while (numBytesRcvd > 0) { // 0 indicates end of stream
        // Echo message back to client
        ssize_t numBytesSent = send(clntSocket, buffer, numBytesRcvd, 0);
        if (numBytesSent < 0) {
            log(ERROR, "send() failed");
            return -1;   // TODO definir codigos de error
        }
        else if (numBytesSent != numBytesRcvd) {
            log(ERROR, "send() sent unexpected number of bytes ");
            return -1;   // TODO definir codigos de error
        }

        // See if there is more data to receive
        numBytesRcvd = recv(clntSocket, buffer, BUFSIZE, 0);
        if (numBytesRcvd < 0) {
            log(ERROR, "recv() failed");
            return -1;   // TODO definir codigos de error
        }
    }

    close(clntSocket);
    return 0;
}


void handle_client_read(struct selector_key *key) {
    int clntSocket = key->fd; // Socket del cliente
    char buffer[BUFSIZE]; // Buffer para el mensaje
    // Recibir mensaje del cliente
    ssize_t numBytesRcvd = recv(clntSocket, buffer, BUFSIZE, 0);
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d", clntSocket);
        return; // TODO definir codigos de error
    }
    else if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        selector_unregister_fd(key->s, clntSocket); // Desregistrar el socket del cliente
        close(clntSocket); // Cerrar el socket del cliente
        return;
    } else {
        // Enviar mensaje de vuelta al cliente
        ssize_t numBytesSent = send(clntSocket, buffer, numBytesRcvd, 0);
        if (numBytesSent < 0) {
            log(ERROR, "send() failed on client socket %d", clntSocket);
            return; // TODO definir codigos de error
        }
        else if (numBytesSent != numBytesRcvd) {
            log(ERROR, "send() sent unexpected number of bytes on client socket %d", clntSocket);
            return; // TODO definir codigos de error
        }
    }

}

void handleTCPEchoClientClose(struct selector_key *key) {
    printf("Closing client socket %d\n", key->fd);
    close(key->fd); // Cerrar el socket del cliente
}

void handleMasterSocketRead(struct selector_key *key) {
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    char *message = "Welcome to the server\r\n";

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

    // mensaje de bienvenida
    if (send(new_socket, message, strlen(message), 0) != strlen(message)) {
        perror("send");
        close(new_socket);
        return;
    }

    puts("Welcome message sent successfully");

    // handler de cliente
    fd_handler client_handler = {
        .handle_read = handle_client_read,
        .handle_close = handleTCPEchoClientClose,
    };

    // crear socket activo
    if (SELECTOR_SUCCESS != selector_register(key->s, new_socket, &client_handler, OP_READ, NULL)) {
        perror("Failed to register client socket");
        close(new_socket);
        return;
    }

    printf("Client socket %d registered with selector\n", new_socket);
}