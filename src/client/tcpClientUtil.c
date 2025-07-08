#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "logger.h"
#include "util.h"
#include "selector.h"
#include "tcpClientUtil.h"
#include "client.h"
#define MAX_ADDR_BUFFER 128
#define CONFIG_VERSION 0x01




int tcpClientSocket(const char *host, const char *service) {
    char addrBuffer[MAX_ADDR_BUFFER];
    struct addrinfo addrCriteria;                   // Criteria for address match
    memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
    addrCriteria.ai_family = AF_UNSPEC;             // v4 or v6 is OK
    addrCriteria.ai_socktype = SOCK_STREAM;         // Only streaming sockets
    addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

    // Get address(es)
    struct addrinfo *servAddr; // Holder for returned list of server addrs
    int rtnVal = getaddrinfo(host, service, &addrCriteria, &servAddr);
    if (rtnVal != 0) {
        log(ERROR, "getaddrinfo() failed %s", gai_strerror(rtnVal))
        return -1;
    }

    int sock = -1;
    for (struct addrinfo *addr = servAddr; addr != NULL && sock == -1; addr = addr->ai_next) {
        // Create a reliable, stream socket using TCP
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock >= 0) {
            errno = 0;
            // Establish the connection to the server
            if ( connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
                log(INFO, "can't connectto %s: %s", printAddressPort(addr, addrBuffer), strerror(errno))
                close(sock); 	// Socket connection failed; try next address
                sock = -1;
            }
        } else {
            log(DEBUG, "Can't create client socket on %s",printAddressPort(addr, addrBuffer))
        }
    }

    freeaddrinfo(servAddr);
    return sock;
}
void client_close(struct selector_key *key){
    const clientData *data = key->data;
    if (data != NULL) {
        log(INFO, "Closing client socket %d", key->fd);
        stm_handler_close(data->stm, key);
    }
}
void client_read(struct selector_key *key){
    clientData *data = key->data;
    stm_handler_read(data->stm, key); //usar enum para detectar errores
}
void client_write(struct selector_key *key){
    clientData *data = key->data;
    stm_handler_write(data->stm, key); //usar enum para detectar errores
}
void client_block(struct selector_key *key){
    log(INFO, "Blocking client socket %d", key->fd);
    // Aquí podrías implementar lógica para bloquear el socket si es necesario
    // Por ejemplo, podrías registrar el socket en un estado de bloqueo o similar
    // En este caso, simplemente estamos registrando la acción
}

unsigned int handleStatsRead(struct selector_key *key) {
    clientData *data = (clientData *) key->data;
    buffer *buf = data->clientBuffer;

    size_t available;
    uint8_t *read_ptr = buffer_read_ptr(buf, &available);

    // Paso 1: leer header (3) + longitud (4)
    if (available < 7) {
        size_t space;
        uint8_t *write_ptr = buffer_write_ptr(buf, &space);
        ssize_t received = recv(key->fd, write_ptr, space, 0);
        if (received <= 0) {
            if (received == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                log(ERROR, "Connection closed or error while receiving stats header/length");
                return ERROR_CLIENT;
            }
            return STATS_READ;
        }
        buffer_write_adv(buf, received);
        return STATS_READ;
    }

    // Header
    uint8_t version = read_ptr[0];
    uint8_t status  = read_ptr[1];
    uint8_t reserved = read_ptr[2];

    if (version != CONFIG_VERSION) {
        log(ERROR, "Invalid version in stats header");
        buffer_read_adv(buf, 7);
        return ERROR_CLIENT;
    }
    if (status != 0x00) {
        log(ERROR, "Server responded with error status in stats request");
        buffer_read_adv(buf, 7);
        return ERROR_CLIENT;
    }

    // Longitud del cuerpo
    uint32_t body_len;
    memcpy(&body_len, read_ptr + 3, 4);
    body_len = ntohl(body_len);

    // Paso 2: esperar a tener el cuerpo completo
    if (available < 7 + body_len) {
        size_t space;
        uint8_t *write_ptr = buffer_write_ptr(buf, &space);
        ssize_t received = recv(key->fd, write_ptr, space, 0);
        if (received <= 0) {
            if (received == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                log(ERROR, "Connection closed or error while receiving stats body");
                return ERROR_CLIENT;
            }
            return STATS_READ;
        }
        buffer_write_adv(buf, received);
        return STATS_READ;
    }

    // Ya tenemos todo el mensaje: header + longitud + cuerpo
    buffer_read_adv(buf, 7); // Consumimos header y longitud

    // Imprimir el cuerpo
    read_ptr = buffer_read_ptr(buf, &available);
    for (uint32_t i = 0; i < body_len && i < available; i++) {
        putchar(read_ptr[i]);
    }
    buffer_read_adv(buf, body_len);

    return DONE;
}
void handleClientClose(const unsigned state, struct selector_key *key) {
    clientData * data = key->data;
    free(data->stm);
    free(data->clientBuffer->data);
    free(data->clientBuffer);
    free(data);
    log(INFO, "Client connection closed for fd %d", key->fd);
    close(key->fd); // Close the socket
    exit( state == DONE ? 0 : 1);
}