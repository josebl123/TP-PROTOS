//
// Created by nicol on 7/7/2025.
//

#include "clientAuth.h"
#include "clientConfig.h"
#include "args.h"
#include "logger.h"
#include "client.h"
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include "clientConfig.h"

#include "server/serverConfigTypes.h"
#include "tcpClientUtil.h"
#include "clientRequest.h"

#define AUTH_VERSION_OFFSET      0
#define AUTH_RSV_OFFSET         1
#define AUTH_STATUS_OFFSET      2
#define AUTH_ROLE_OFFSET        3
#define AUTH_HEADER_LEN         4
#define AUTH_REQ_VERSION_OFFSET      0
#define AUTH_REQ_RSV_OFFSET         1
#define AUTH_REQ_USERLEN_OFFSET     2
#define AUTH_REQ_USERNAME_OFFSET    3

unsigned handle_auth_read(client_data *data) {

    size_t write_limit;
    uint8_t *write_ptr = buffer_write_ptr(data->client_buffer, &write_limit);
    ssize_t num_bytes_rcvd = recv(clnt_socket, write_ptr, write_limit, 0);

    if (num_bytes_rcvd <= 0) {
        if (num_bytes_rcvd == 0) {
                  return DONE;
        } else {
            log(ERROR, "recv() failed on client socket %d: %s", clnt_socket, strerror(errno));
            return ERROR_CLIENT;
        }
    }

    buffer_write_adv(data->client_buffer, num_bytes_rcvd);

    size_t available;
    uint8_t *read_ptr = buffer_read_ptr(data->client_buffer, &available);
    if (available < AUTH_HEADER_LEN) return handle_auth_read(data);

    uint8_t version = read_ptr[AUTH_VERSION_OFFSET];
    uint8_t rsv     = read_ptr[AUTH_RSV_OFFSET];
    uint8_t status  = read_ptr[AUTH_STATUS_OFFSET];
    uint8_t role    = read_ptr[AUTH_ROLE_OFFSET];

    if (version != VERSION || rsv != RSV) {
        log(ERROR, "Invalid version or reserved byte");
        return ERROR_CLIENT;
    }


    buffer_read_adv(data->client_buffer, AUTH_HEADER_LEN);


    if (status != STATUS_OK) {
        failure_response_print(status);
        return ERROR_CLIENT;
    }
    if (role == ROLE_USER) {
        if (data->args->flag == NULL || strcmp(data->args->flag, "default") != 0) {
            printf("### Unauthorized\n");
            return ERROR_CLIENT;
        }

        printf("## Authentication successful for user role\n");
        return handle_stats_read(data);
    }
    if (role == ROLE_ADMIN) {
        buffer_reset(data->client_buffer);
        printf("## Authentication successful for Admin role\n");

        return handle_request_write(data);
    }

    log(ERROR, "Unknown role received: %02X", role);

    return ERROR_CLIENT;
}
unsigned handle_auth_config_send(client_data *data, uint8_t *response, size_t responseSize) {

    ssize_t bytes_sent = send(clnt_socket, response, responseSize, 0);
    if (bytes_sent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clnt_socket, strerror(errno));
        free(response);
        return ERROR_CLIENT;
    }
    if (bytes_sent == 0) {
        free(response);
        return DONE; // Connection closed
    }

    if ((size_t)bytes_sent < responseSize) {
        return handle_auth_config_send(data, response + bytes_sent, responseSize - bytes_sent); // Partial send, wait for next write
    }

    free(response);
    return handle_auth_read(data);
}

unsigned handle_auth_write(client_data *data) {

    if (data->args->username == NULL || data->args->password == NULL) {
        log(ERROR, "Username or password not set");
        return ERROR_CLIENT;
    }

    uint8_t username_length = strlen(data->args->username);
    uint8_t password_length = strlen(data->args->password);

    int total_length = AUTH_REQ_USERNAME_OFFSET + username_length + 1 + password_length;

    uint8_t *response = malloc(total_length);
    if (response == NULL) {
        log(ERROR, "Memory allocation failed");
        return ERROR_CLIENT;
    }

    int offset = 0;
    response[offset++] = VERSION;
    response[offset++] = RSV;
    response[offset++] = username_length;
    memcpy(response + offset, data->args->username, username_length);
    offset += username_length;
    response[offset++] = password_length;
    memcpy(response + offset, data->args->password, password_length);

   return handle_auth_config_send(data, response, total_length);
}