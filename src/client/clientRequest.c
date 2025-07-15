// clientRequest.c

#include "clientRequest.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "logger.h"
#include "args.h"
#include "client.h"
#include "clientConfig.h"

#define VERSION_OFFSET         0
#define RSV_OFFSET             1
#define OPTION_OFFSET          2
#define USERNAME_LENGTH_OFFSET 3
#define HEADER_LENGTH          4 // VERSION + RSV + OPTION + USERNAME_LENGTH
#define RESPONSE_HEADER_LENGTH 3 // VERSION + RSV + OPTION

#define OPTION_STATS  0x00
#define OPTION_CONFIG 0xFF
#include "tcpClientUtil.h"

unsigned handle_request_read(client_data *data) {

    size_t write_limit;
    uint8_t *write_ptr = buffer_write_ptr(data->client_buffer, &write_limit);
    const ssize_t num_bytes_rcvd = recv(clnt_socket, write_ptr, write_limit, 0);


    if (num_bytes_rcvd < 0) {
        log(ERROR, "recv() failed on client socket %d: %s", clnt_socket, strerror(errno));
        return ERROR_CLIENT;
    }
    if (num_bytes_rcvd == 0) {
        return DONE;
    }
    buffer_write_adv(data->client_buffer, num_bytes_rcvd);
    size_t available;
    buffer_read_ptr(data->client_buffer, &available);
    if (available < RESPONSE_HEADER_LENGTH) {
        return handle_request_read(data); // Not enough data yet
    }

    if(buffer_read(data->client_buffer) != VERSION) {
        log(ERROR, "Invalid version in authentication request from client socket %d", clnt_socket);
        return ERROR_CLIENT;
    }
    if (buffer_read(data->client_buffer) != RSV) {
        log(ERROR, "Invalid reserved byte in authentication request from client socket %d", clnt_socket);
        return ERROR_CLIENT;
    }

    uint8_t status = buffer_read(data->client_buffer);
    if(status == OPTION_CONFIG) {
        return handle_config_write(data);
    }
    if(status == OPTION_STATS){
        return handle_stats_read(data);
    }
    if (status != OPTION_STATS && status != OPTION_CONFIG) {
        failure_response_print(status);
        return ERROR_CLIENT;
    }
    return ERROR_CLIENT;
}

unsigned handle_request_send(client_data * data) {
    size_t available_bytes;
    uint8_t *read_ptr = buffer_read_ptr(data->client_buffer, &available_bytes);
    ssize_t bytes_sent = send(clnt_socket, read_ptr, available_bytes, 0);
    if (bytes_sent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clnt_socket, strerror(errno));
        return ERROR_CLIENT;
    }
    if (bytes_sent == 0) {
        return DONE;

    }
    buffer_read_adv(data->client_buffer, bytes_sent); // Avanzar el puntero de lectura del buffer
    if((size_t)bytes_sent < available_bytes) {
      log(INFO, "Partial send, waiting for next write");
        return handle_request_send(data);
    }
    return handle_request_read(data);
}
unsigned handle_request_write(client_data *data) {


    unsigned long username_length = data->args->target_user ? strlen(data->args->target_user) : 0;
    int total_length = HEADER_LENGTH + username_length + 1; // +1 por el null terminator

    buffer_reset(data->client_buffer);
    size_t available_bytes;
    uint8_t * write_ptr = buffer_write_ptr(data->client_buffer, &available_bytes);
    if( available_bytes < (size_t)total_length ){
        log(ERROR, "Not enough space in buffer to write request: %d bytes needed, %zu available", total_length, available_bytes);
        return ERROR_CLIENT;
    }

    write_ptr[VERSION_OFFSET]         = VERSION;
    write_ptr[RSV_OFFSET]             = RSV;
    write_ptr[OPTION_OFFSET]          = data->args->stats ? OPTION_STATS : OPTION_CONFIG;
    write_ptr[USERNAME_LENGTH_OFFSET] = username_length;



    if (username_length > 0) {
        memcpy(write_ptr + HEADER_LENGTH, data->args->target_user, username_length);
    }
    write_ptr[HEADER_LENGTH + username_length] = '\0'; // Null terminator
    buffer_write_adv(data->client_buffer, total_length);
    return handle_request_send(data);
}