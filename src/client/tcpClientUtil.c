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

static enum {
    STATS_READING_HEADER,
    STATS_READING_BODY,
    STATS_DONE
} state = STATS_READING_HEADER;

int tcp_client_socket(const char *host, const char *service) {
    struct addrinfo addr_criteria = {0};
    addr_criteria.ai_family = AF_UNSPEC;
    addr_criteria.ai_socktype = SOCK_STREAM;
    addr_criteria.ai_protocol = IPPROTO_TCP;

    struct addrinfo *serv_addr;
    const int rtn_val = getaddrinfo(host, service, &addr_criteria, &serv_addr);
    if (rtn_val != 0) {
        log(ERROR, "getaddrinfo() failed %s", gai_strerror(rtn_val));
        return -1;
    }

    int sock = -1;
    for (struct addrinfo *addr = serv_addr; addr != NULL && sock == -1; addr = addr->ai_next) {
        char addr_buffer[MAX_ADDR_BUFFER];
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock >= 0) {
            errno = 0;
            if (connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
                close(sock);
                sock = -1;
                printf("Connection failed on %s: %s\n", print_address_port(addr, addr_buffer), strerror(errno));
            }
        } else {
           printf( "Can't create client socket on %s", print_address_port(addr, addr_buffer));
        }
    }

    freeaddrinfo(serv_addr);
    return sock;
}


void failure_response_print(int response) {
    if (response == STATUS_BAD_REQUEST) {
        printf("#Fail, error: Bad request\n");
    } else {
        printf("#Fail, error: Server general failure\n");
    }
}

void handle_client_close(const unsigned state, client_data * data) {
    fflush(stdout);
    free(data->stm);
    free(data->client_buffer->data);
    free(data->client_buffer);
    free(data);
    close(clnt_socket);
    exit(state == DONE ? 0 : 1);
}
unsigned handle_stats_read_rec(client_data *data, unsigned state, uint32_t * expected_body_len, uint32_t  bytes_read) {
    buffer *buf = data->client_buffer;

    while (1) {
        size_t available;
        const uint8_t *read_ptr = buffer_read_ptr(buf, &available);

        if (state == STATS_READING_HEADER) {
            if (available < STATS_TOTAL_HEADER) {
                // Leer más datos
                size_t space;
                uint8_t *write_ptr = buffer_write_ptr(buf, &space);
                const ssize_t received = recv(clnt_socket, write_ptr, space, 0);
                if (received <= 0) {
                    return DONE;
                }
                buffer_write_adv(buf, received);
                return handle_stats_read_rec(data, state, expected_body_len, bytes_read);
            }

            // Procesar header
            const uint8_t version = read_ptr[0];
            const uint8_t reserved = read_ptr[1];
            const uint8_t status = read_ptr[2];

            if (version != CONFIG_VERSION || reserved != RSV) {
                buffer_read_adv(buf, STATS_TOTAL_HEADER);
                return ERROR_CLIENT;
            }

            if (status != STATS_STATUS_OK) {
                failure_response_print(status);
                buffer_read_adv(buf, STATS_TOTAL_HEADER);
                return ERROR_CLIENT;
            }

            // Longitud del cuerpo
            memcpy(expected_body_len, read_ptr + STATS_HEADER_LEN, STATS_BODYLEN_LEN);
            *expected_body_len = ntohl(*expected_body_len);
            buffer_read_adv(buf, STATS_TOTAL_HEADER);
            state = STATS_READING_BODY;
            continue;
        }

        if (state == STATS_READING_BODY) {
            // Leer más datos si no hay disponibles
            if (available == 0) {
                size_t space;
                uint8_t *write_ptr = buffer_write_ptr(buf, &space);
                const ssize_t received = recv(clnt_socket, write_ptr, space, 0);
                if (received <= 0) {
                    return DONE;
                }
                buffer_write_adv(buf, received);
                continue; // volver al while
            }

            // Imprimir lo que haya disponible, hasta completar el cuerpo
            const uint32_t remaining = *expected_body_len - bytes_read;
            const uint32_t to_print = available < remaining ? available : remaining;

            fwrite(read_ptr, 1, to_print, stdout);
            fflush(stdout);

            buffer_read_adv(buf, to_print);
            bytes_read += to_print;

            if (bytes_read >= *expected_body_len) {
                state = STATS_DONE;
            } else {
                return handle_stats_read_rec(data, state, expected_body_len, bytes_read);
            }
        }

        if (state == STATS_DONE) {
            // Reset para futuras llamadas
            state = STATS_READING_HEADER;
            *expected_body_len = 0;
            bytes_read = 0;
            return DONE;
        }
    }
}


unsigned handle_stats_read(client_data *data) {

    // Estado del cliente
    state = STATS_READING_HEADER;
    uint32_t expected_body_len = 0;

    return handle_stats_read_rec(data, state, &expected_body_len, 0);
}


