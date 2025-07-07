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
    clientData *data = key->data;
    log(INFO, "Blocking client socket %d", key->fd);
    // Aquí podrías implementar lógica para bloquear el socket si es necesario
    // Por ejemplo, podrías registrar el socket en un estado de bloqueo o similar
    // En este caso, simplemente estamos registrando la acción
}