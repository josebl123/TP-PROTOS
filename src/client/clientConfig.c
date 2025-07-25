//
// Created by nicol on 7/7/2025.
//

#include "clientConfig.h"
#include "args.h"
#include "logger.h"
#include "client.h"
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

#include "server/serverConfigTypes.h"
#include "tcpClientUtil.h"

enum OPTIONS {
    OPTION_BUFFER_SIZE = 0x00, // Read or write buffer size
    OPTION_ACCEPTS_NO_AUTH = 0x01, // Read configuration
    OPTION_NOT_ACCEPTS_NO_AUTH = 0x02, // Write configuration
    OPTION_ADD_USER = 0x03, // Read stats
    OPTION_REMOVE_USER = 0x04, // Done with configuration
    OPTION_MAKE_ADMIN = 0x05, // Make user admin
};
#define OFFSET_VERSION         0
#define OFFSET_RSV             1
#define OFFSET_OPTION          2
#define OFFSET_USERLEN         3
#define OFFSET_USERNAME        4

#define BUFFER_SIZE_MSG_LEN    11
#define BUFFER_SIZE_OFFSET_0   7
#define BUFFER_SIZE_OFFSET_1   8
#define BUFFER_SIZE_OFFSET_2   9
#define BUFFER_SIZE_OFFSET_3   10

#define ACCEPTS_NO_AUTH_MSG_LEN 8

#define ADD_USER_BASE_LEN      5
#define REMOVE_USER_BASE_LEN   5
#define MAKE_ADMIN_BASE_LEN    5


unsigned handle_config_read(client_data *data) {

    size_t write_limit;
    uint8_t *write_ptr = buffer_write_ptr(data->client_buffer, &write_limit);
    const ssize_t num_bytes_rcvd = recv(clnt_socket, write_ptr, write_limit, 0);
    buffer_write_adv(data->client_buffer, num_bytes_rcvd);

    if (num_bytes_rcvd < 0) {
        log(ERROR, "recv() failed on client socket %d: %s", clnt_socket, strerror(errno));
        return ERROR_CLIENT; // TODO definir codigos de error
    }

    if (num_bytes_rcvd == 0) {
        return DONE;
    }
    if(buffer_read(data->client_buffer) != VERSION) {
        log(ERROR, "Invalid version in authentication request from client socket %d", clnt_socket);
        return ERROR_CLIENT; // Abortamos si la versión no es correcta
    }
    if (buffer_read(data->client_buffer) != RSV) {
        log(ERROR, "Invalid reserved byte in authentication request from client socket %d", clnt_socket);
        return ERROR_CLIENT; // Abortamos si el byte reservado no es correcto
    }
    uint8_t option = buffer_read(data->client_buffer);
    int status = buffer_read(data->client_buffer);
    switch (option) {
        case OPTION_BUFFER_SIZE:
            if (status == STATUS_OK) {
                printf("#Ok, buffer size changed successfully\n");
            } else {
                printf("#Fail, buffer size change failed\n");
                failure_response_print(status);
            }
            return DONE;

        case OPTION_ACCEPTS_NO_AUTH:
            if (status == STATUS_OK) {
                printf("#Ok, server now accepts no auth connections successfully\n");
            } else {
                printf("#Fail, accepts_no_auth change failed\n");
                failure_response_print(status);
            }
            return DONE;

        case OPTION_NOT_ACCEPTS_NO_AUTH:
            if (status == STATUS_OK) {
                printf("#Ok, server only accepts auth connections successfully\n");
            } else {
                printf("#Fail, not_accepts_no_auth change failed\n");
                failure_response_print(status);
            }
            return DONE;

        case OPTION_ADD_USER:
            if (status == STATUS_OK) {
                printf("#Ok, user added!\n");
            } else {
                printf("#Fail, error adding user\n");
                failure_response_print(status);
            }
            return DONE;

        case OPTION_REMOVE_USER:
            if (status == STATUS_OK) {
                printf("#Ok, user removed!\n");
            } else {
                printf("#Fail, error removing user\n");
                failure_response_print(status);
            }
            return DONE;

        case OPTION_MAKE_ADMIN:
            if (status == STATUS_OK) {
                printf("#Ok, user is now admin!\n");
            } else {
                printf("#Fail, error making user admin\n");
                failure_response_print(status);
            }
            return DONE;
        default:
            printf("#Fail, unknown option\n");
            return DONE;
    }
  }
  unsigned handle_config_send(client_data *data, char *response, size_t responseSize) {

    ssize_t bytes_sent = send(clnt_socket, response, responseSize, 0);
    if (bytes_sent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clnt_socket, strerror(errno));
        return ERROR_CLIENT;
    }
    if (bytes_sent == 0) {
        return DONE; // Connection closed
    }
    if((size_t)bytes_sent < responseSize) {
        return handle_config_send(data, response + bytes_sent, responseSize - bytes_sent); // Partial send, wait for next write
    }
    return handle_config_read(data);
 }

unsigned handle_config_write(client_data *data) {

    char *response = NULL;
    int responseSize = 0;

    switch (data->args->type) {
        case BUFFER_SIZE:
            response = calloc(BUFFER_SIZE_MSG_LEN, 1);
            response[OFFSET_VERSION] = VERSION;
            response[OFFSET_RSV] = RSV;
            response[OFFSET_OPTION] = OPTION_BUFFER_SIZE;
            response[BUFFER_SIZE_OFFSET_0] = data->args->buffer_size >> 24;
            response[BUFFER_SIZE_OFFSET_1] = data->args->buffer_size >> 16;
            response[BUFFER_SIZE_OFFSET_2] = data->args->buffer_size >> 8;
            response[BUFFER_SIZE_OFFSET_3] = data->args->buffer_size & 0xFF;
            responseSize = BUFFER_SIZE_MSG_LEN;
            break;
        case ACCEPTS_NO_AUTH:
            response = calloc(ACCEPTS_NO_AUTH_MSG_LEN, 1);
            response[OFFSET_VERSION] = VERSION;
            response[OFFSET_RSV] = RSV;
            response[OFFSET_OPTION] = data->args->accepts_no_auth ? OPTION_ACCEPTS_NO_AUTH : OPTION_NOT_ACCEPTS_NO_AUTH;
            responseSize = ACCEPTS_NO_AUTH_MSG_LEN;
            break;
        case ADD_USER: {
            int user_len = strlen(data->args->user.name);
            int pass_len = strlen(data->args->user.pass);
            responseSize = ADD_USER_BASE_LEN + user_len + pass_len;
            response = calloc(responseSize, 1);
            response[OFFSET_VERSION] = VERSION;
            response[OFFSET_RSV] = RSV;
            response[OFFSET_OPTION] = OPTION_ADD_USER;
            response[OFFSET_USERLEN] = user_len;
            memcpy(response + OFFSET_USERNAME, data->args->user.name, user_len);
            response[OFFSET_USERNAME + user_len] = pass_len;
            memcpy(response + OFFSET_USERNAME + user_len + 1, data->args->user.pass, pass_len);
            break;
        }
        case REMOVE_USER: {
            int user_len = strlen(data->args->user.name);
            responseSize = REMOVE_USER_BASE_LEN + user_len;
            response = calloc(responseSize, 1);
            response[OFFSET_VERSION] = VERSION;
            response[OFFSET_RSV] = RSV;
            response[OFFSET_OPTION] = OPTION_REMOVE_USER;
            response[OFFSET_USERLEN] = user_len;
            memcpy(response + OFFSET_USERNAME, data->args->user.name, user_len);
            break;
        }
        case MAKE_ADMIN: {
            int user_len = strlen(data->args->user.name);
            responseSize = MAKE_ADMIN_BASE_LEN + user_len;
            response = calloc(responseSize, 1);
            response[OFFSET_VERSION] = VERSION;
            response[OFFSET_RSV] = RSV;
            response[OFFSET_OPTION] = OPTION_MAKE_ADMIN;
            response[OFFSET_USERLEN] = user_len;
            memcpy(response + OFFSET_USERNAME, data->args->user.name, user_len);
            break;
        }
        default:
            log(ERROR, "Unknown configuration option: %d", data->args->type);
            return ERROR_CLIENT;
    }
    return handle_config_send(data, response, responseSize);
}




