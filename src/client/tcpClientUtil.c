#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "logger.h"
#include "util.h"
#include "tcpClientUtil.h"
#include "client.h"

#define MAX_ADDR_BUFFER      128
#define CONFIG_VERSION       0x01
#define RSV                 0x00 // Asegúrate de definir RSV si no está en los headers

// Offsets y tamaños para el header de stats
#define STATS_HEADER_LEN     3
#define STATS_BODYLEN_LEN    4
#define STATS_TOTAL_HEADER   (STATS_HEADER_LEN + STATS_BODYLEN_LEN)
#define STATS_STATUS_OK      0x00

int tcpClientSocket(const char *host, const char *service) {
    struct addrinfo addrCriteria = {0};
    addrCriteria.ai_family = AF_UNSPEC;
    addrCriteria.ai_socktype = SOCK_STREAM;
    addrCriteria.ai_protocol = IPPROTO_TCP;

    struct addrinfo *servAddr;
    const int rtnVal = getaddrinfo(host, service, &addrCriteria, &servAddr);
    if (rtnVal != 0) {
        log(ERROR, "getaddrinfo() failed %s", gai_strerror(rtnVal));
        return -1;
    }

    int sock = -1;
    for (struct addrinfo *addr = servAddr; addr != NULL && sock == -1; addr = addr->ai_next) {
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock >= 0) {
            errno = 0;
            if (connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
                close(sock);
                sock = -1;
            }
        } else {
            char addrBuffer[MAX_ADDR_BUFFER];
            log(DEBUG, "Can't create client socket on %s", printAddressPort(addr, addrBuffer));
        }
    }

    freeaddrinfo(servAddr);
    return sock;
}


void failure_response_print(int response) {
    if (response == STATUS_BAD_REQUEST) {
        printf("#Fail, error: Bad request\n");
    } else {
        printf("#Fail, error: Server general failure\n");
    }
}

void handleClientClose(const unsigned state, clientData * data) {
    free(data->stm);
    free(data->clientBuffer->data);
    free(data->clientBuffer);
    free(data);
    close(clntSocket);
    exit(state == DONE ? 0 : 1);
}


unsigned handleStatsRead(clientData * data) {
    buffer *buf = data->clientBuffer;

    size_t available;
    const uint8_t *read_ptr = buffer_read_ptr(buf, &available);

    // Paso 1: leer header (3) + longitud (4)
    if (available < STATS_TOTAL_HEADER) {
        size_t space;
        uint8_t *write_ptr = buffer_write_ptr(buf, &space);
        const ssize_t received = recv(clntSocket, write_ptr, space, 0);
        if (received <= 0) {
            if (received == 0) {
                log(ERROR, "Connection closed or error while receiving stats header/length");
               return DONE;
            }
            return ERROR_CLIENT;
        }
        buffer_write_adv(buf, received);
        return handleStatsRead(data);
    }
    int offset = 0;
    // Header
    const uint8_t version  = read_ptr[offset++];
    const uint8_t reserved = read_ptr[offset++];
    const uint8_t status   = read_ptr[offset];

    if (version != CONFIG_VERSION) {
        log(ERROR, "Invalid version in stats header");
        buffer_read_adv(buf, STATS_TOTAL_HEADER);
        return ERROR_CLIENT;
    }
    if (reserved != RSV) {
        log(ERROR, "Invalid reserved byte in stats header");
        buffer_read_adv(buf, STATS_TOTAL_HEADER);
        return ERROR_CLIENT;
    }
    if (status != STATS_STATUS_OK) {
        failure_response_print(status);
        buffer_read_adv(buf, STATS_TOTAL_HEADER);
        return ERROR_CLIENT;
    }
    printf("#Ok, Stats fetched successfully\n");

    // Longitud del cuerpo
    uint32_t body_len;
    memcpy(&body_len, read_ptr + STATS_HEADER_LEN, STATS_BODYLEN_LEN);
    body_len = ntohl(body_len);

    // Paso 2: esperar a tener el cuerpo completo
    if (available < STATS_TOTAL_HEADER + body_len) {
        size_t space;
        uint8_t *write_ptr = buffer_write_ptr(buf, &space);
        const ssize_t received = recv(clntSocket, write_ptr, space, 0);
        if (received <= 0) {
            if (received == 0 ) {
                log(ERROR, "Connection closed or error while receiving stats body");
                return DONE;
            }
            return ERROR_CLIENT;
        }
        buffer_write_adv(buf, received);
        return handleStatsRead(data);
    }

    // Ya tenemos todo el mensaje: header + longitud + cuerpo
    buffer_read_adv(buf, STATS_TOTAL_HEADER);

    // Imprimir el cuerpo
    read_ptr = buffer_read_ptr(buf, &available);
    for (uint32_t i = 0; i < body_len && i < available; i++) {
        putchar(read_ptr[i]);
    }
    buffer_read_adv(buf, body_len);

    return DONE;
}
