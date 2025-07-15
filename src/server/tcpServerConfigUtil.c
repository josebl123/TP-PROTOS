#include "tcpServerConfigUtil.h"
#include "../utils/logger.h"
#include "../utils/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "rbt.h"
#include "../metrics/metrics.h"
#include "utils/user_metrics_table.h"
#include "server.h"
#include "serverConfigActions.h"
#include "serverConfigTypes.h"
#include <time.h>

#include "args.h"

#define MAX_ADDR_BUFFER 128
#define MIN_CONFIG_READ_LENGTH 3 // Minimum bytes to read for config (version, rsv, userlen)
#define CONFIG_TIMEOUT_SEC 60 // Timeout for incomplete config messages


static char addr_buffer[MAX_ADDR_BUFFER];


unsigned send_bad_request(struct selector_key * key) {
    return generic_write(key, CONFIG_DONE, BAD_REQUEST_ERROR);
}

unsigned attempt_send_bad_request_error(struct selector_key *key) {
    const client_config_data *data = key->data;

    buffer_reset(data->client_buffer);
    buffer_write(data->client_buffer, CONFIG_VERSION);
    buffer_write(data->client_buffer, RSV);
    buffer_write(data->client_buffer,   ERROR );
    buffer_write(data->client_buffer, ROLE_USER); // status fail
    return send_bad_request(key);
}

unsigned send_auth_fail(struct selector_key *key) {
    const client_config_data *data = key->data;
    const int clnt_socket = key->fd;

    buffer_reset(data->client_buffer);
    buffer_write(data->client_buffer, CONFIG_VERSION);
    buffer_write(data->client_buffer, RSV);
    buffer_write(data->client_buffer, data->response_code);

    size_t available_bytes;
    const uint8_t *ptr = buffer_read_ptr(data->client_buffer, &available_bytes);
    const ssize_t sent = send(clnt_socket, ptr, available_bytes, 0);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            return BAD_REQUEST_ERROR;
        }
        log(ERROR, "send() failed on client socket %d: %s", clnt_socket, strerror(errno));
        return CONFIG_DONE;
    }
    if (sent == 0) {
        return CONFIG_DONE;
    }
    buffer_read_adv(data->client_buffer, sent); // Avanzar el puntero de lectura del buffer
    return CONFIG_DONE;
}

unsigned handle_auth_config_write(struct selector_key *key) {
    const int clnt_socket = key->fd;
    const client_config_data *data = key->data;
    size_t available_bytes;
    const uint8_t *ptr = buffer_read_ptr(data->client_buffer, &available_bytes);
    const ssize_t sent = send(clnt_socket,ptr, available_bytes, 0);

    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            return AUTH_DONE;
        }
        log(ERROR, "send() failed on client socket %d: %s", clnt_socket, strerror(errno));
        return CONFIG_DONE;
    }
    if (sent == 0) {
        return CONFIG_DONE;
    }
    buffer_read_adv(data->client_buffer, sent); // Avanzar el puntero de lectura del buffer
    if (sent < (ssize_t)available_bytes) {
        return AUTH_DONE; // Partial send, wait for next write
    }

    if (data->role == ROLE_INVALID) {
        log(ERROR, "Authentication failed for client socket %d", clnt_socket);
        return send_auth_fail(key);
    }

    if (data->role != ROLE_ADMIN) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {;
            log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
            return ERROR_CLIENT;
        }
        return attempt_user_metrics_write(key);
    }
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
        return ERROR_CLIENT;
    }
    return ADMIN_INITIAL_REQUEST_READ;
}

unsigned attempt_auth_config_write (struct selector_key *key) {
    client_config_data *data = key->data;

    buffer_reset(data->client_buffer);
    buffer_write(data->client_buffer, CONFIG_VERSION);
    buffer_write(data->client_buffer, RSV);
    data->response_code = (data->role != ROLE_INVALID ? STATUS_OK : STATUS_BAD_REQUEST);
    buffer_write(data->client_buffer, data->response_code);
    if (data->role != ROLE_INVALID) {
        buffer_write(data->client_buffer, data->role);
    }
    return handle_auth_config_write(key);
}

unsigned handle_auth_config_read(struct selector_key *key) {
    const int clnt_socket = key->fd;
    client_config_data *data = key->data;
    size_t write_limit;

    uint8_t *read_ptr = buffer_write_ptr(data->client_buffer, &write_limit);
    const ssize_t num_bytes_rcvd = recv(clnt_socket, read_ptr, write_limit, 0);

    if (num_bytes_rcvd <= 0) {
        log(num_bytes_rcvd == 0 ? INFO : ERROR, "recv() failed or closed on client socket %d", clnt_socket);
        return CONFIG_DONE;
    }

    buffer_write_adv(data->client_buffer, num_bytes_rcvd);

    size_t available;
    const uint8_t *ptr = buffer_read_ptr(data->client_buffer, &available);

    // Se necesitan al menos 3 bytes para version, rsv, userlen
    if (available < MIN_CONFIG_READ_LENGTH) return READ_CREDENTIALS;

    const uint8_t version = ptr[0];
    if (version != CONFIG_VERSION) {
        if (selector_set_interest_key(key, OP_WRITE)!= SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
            return ERROR_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }
    const uint8_t rsv = ptr[1];
    if (rsv != RSV) {
        if (selector_set_interest_key(key, OP_WRITE)!= SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
            return ERROR_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }
    const uint8_t userlen = ptr[2];

    // Se necesitan los bytes del username y al menos 1 byte para passlen
    if (available < MIN_CONFIG_READ_LENGTH + (size_t)userlen + 1) return READ_CREDENTIALS;

    const uint8_t passlen = ptr[MIN_CONFIG_READ_LENGTH + userlen];

    // Se necesitan los bytes del password
    if (available < MIN_CONFIG_READ_LENGTH + (size_t)userlen + 1 + passlen) return READ_CREDENTIALS;
    char username[MAX_USERNAME_LEN + 1] = {0};
    memcpy(username, ptr + MIN_CONFIG_READ_LENGTH, userlen);
    username[userlen] = '\0';
    data->userlen = userlen;

    char password[MAX_PASSWORD_LEN + 1] = {0};
    memcpy(password, ptr + MIN_CONFIG_READ_LENGTH + userlen + 1, passlen);
    password[passlen] = '\0';

    // Avanzar el buffer
    buffer_read_adv(data->client_buffer, MIN_CONFIG_READ_LENGTH + userlen + 1 + passlen);

    strncpy(data->auth_info.username, username, MAX_USERNAME_LEN);
    strncpy(data->auth_info.password, password, MAX_PASSWORD_LEN);


    if (socks_args == NULL) { log(ERROR, "socks_args is NULL"); return CONFIG_DONE; }

    bool found = false;
    for (size_t i = 0; socks_args->users[i].name != NULL && i < MAX_USERS; i++) {
        if (strncmp(socks_args->users[i].name, data->auth_info.username, MAX_USERNAME_LEN) == 0 &&
            strncmp(socks_args->users[i].pass, data->auth_info.password, MAX_PASSWORD_LEN) == 0) {
            found = true;
            data->role = socks_args->users[i].is_admin ? ROLE_ADMIN : ROLE_USER;
            break;
        }
    }
    if (!found) {
        data->role = ROLE_INVALID;
    }

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
        return ERROR_CLIENT;
    }

    return attempt_auth_config_write(key);
}



void handle_config_done(const unsigned state, struct selector_key *key) {
    if (state == ERROR_CONFIG_CLIENT) {
        log(ERROR, "Closing remote socket %d due to error", key->fd);
    }
    selector_unregister_fd(key->s, key->fd);
}

unsigned handle_admin_initial_request_write(struct selector_key *key) {
    const int clnt_socket = key->fd;
    const client_config_data *data = key->data;
    size_t available_bytes;
    const uint8_t *ptr = buffer_read_ptr(data->client_buffer, &available_bytes);
    const ssize_t sent = send(clnt_socket,ptr, available_bytes, 0);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            return ADMIN_INITIAL_REQUEST_WRITE;
        }
        log(ERROR, "send() failed on client socket %d: %s", clnt_socket, strerror(errno));
        return CONFIG_DONE;
    }
    if (sent == 0) {
        return CONFIG_DONE;
    }
    buffer_read_adv(data->client_buffer, sent); // Avanzar el puntero de lectura del buffer
    if (sent < (ssize_t)available_bytes) {
        return ADMIN_INITIAL_REQUEST_WRITE; // Partial send, wait for next write
    }


    if (data->admin_cmd == GLOBAL_STATS) { // STATS
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
            return ERROR_CLIENT;
        }
        return attempt_admin_metrics_write(key);
    }
    if (data->admin_cmd == CONFIG) { // CONFIG
        if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
            return ERROR_CLIENT;
        }
        return ADMIN_COMMAND_READ;
    }
    return CONFIG_DONE;
}


unsigned admin_attempt_initial_request_write(struct selector_key *key) {
    const client_config_data *data = key->data;
    buffer_reset(data->client_buffer);
    buffer_write(data->client_buffer, CONFIG_VERSION);
    buffer_write(data->client_buffer, RSV);
    if (data->admin_cmd == GLOBAL_STATS) {
        buffer_write(data->client_buffer, GLOBAL_STATS);
    } else if (data->admin_cmd == CONFIG) {
        buffer_write(data->client_buffer, CONFIG);
    } else {
        buffer_write(data->client_buffer, 0xFF); // status fail
    }

    return handle_admin_initial_request_write(key);
}

unsigned handle_admin_initial_request_read(struct selector_key *key) {
    client_config_data *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->client_buffer, &available);
    const ssize_t num_bytes_rcvd = recv(fd, ptr, available, 0);
    if (num_bytes_rcvd <= 0) {
        if (num_bytes_rcvd == 0) {
    } else {
        log(ERROR, "recv() failed on client socket %d: %s", fd, strerror(errno));
    }
        return CONFIG_DONE;
    }
    buffer_write_adv(data->client_buffer, num_bytes_rcvd);

    size_t read_available;
    const uint8_t *read_ptr = buffer_read_ptr(data->client_buffer, &read_available);
    if (read_available < 4) return ADMIN_INITIAL_REQUEST_READ;
    const uint8_t version = read_ptr[0];
    const uint8_t rsv = read_ptr[1];
    const uint8_t cmd = read_ptr[2]; // 0=stats, 1=config
    const uint8_t ulen = read_ptr[3];

    if (version != CONFIG_VERSION) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", fd);
            return ERROR_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }
    if (rsv != RSV) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", fd);
            return ERROR_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }

    if (read_available < 4 + (size_t)ulen) return ADMIN_INITIAL_REQUEST_READ;
    buffer_read_adv(data->client_buffer, 4);

    char username[MAX_USERNAME_LEN + 1] = {0};
    if (ulen > 0) memcpy(username,  buffer_read_ptr(data->client_buffer, &available), ulen);
    data->target_ulen = ulen;

    // Save info in client_data
    data->admin_cmd = cmd;
    strncpy(data->target_username, username, ulen);

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", fd);
        return ERROR_CLIENT;
    }
    return admin_attempt_initial_request_write(key);
}

unsigned handle_admin_config_read(struct selector_key *key) {
    const client_config_data *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->client_buffer, &available);

    const ssize_t num_bytes_rcvd = recv(fd, ptr, available < 3 ? available : 3, 0);
    if (num_bytes_rcvd <= 0) {
        if (num_bytes_rcvd == 0) {
            return CONFIG_DONE;
        }
        log(ERROR, "recv() failed on client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }

    buffer_write_adv(data->client_buffer, num_bytes_rcvd);

    size_t read_available;
    buffer_read_ptr(data->client_buffer, &read_available);

    if (read_available < MIN_CONFIG_READ_LENGTH) return ADMIN_COMMAND_READ; // versión, rsv, código (1 byte)

    const uint8_t version = buffer_read(data->client_buffer);
    if (version != CONFIG_VERSION) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", fd);
            return ERROR_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }
    const uint8_t rsv = buffer_read(data->client_buffer);
    if (rsv != RSV) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", fd);
            return ERROR_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }
    const uint8_t code = buffer_read(data->client_buffer);
    if ( code > ADMIN_CMD_MAKE_ADMIN) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", fd);
            return ERROR_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }

    switch (code) {
        case ADMIN_CMD_CHANGE_BUFFER_SIZE: // change buffer size
            if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", fd);
                return ERROR_CLIENT;
            }
        return ADMIN_BUFFER_SIZE_CHANGE_READ;
        case ADMIN_CMD_ACCEPTS_NO_AUTH: // accepts-no-auth
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", fd);
                return ERROR_CLIENT;
            }
        return attempt_admin_accepts_auth_write( key, true);
        case ADMIN_CMD_REJECTS_NO_AUTH: // not-accepts-no-auth
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", fd);
                return ERROR_CLIENT;
            }
        return attempt_admin_accepts_auth_write( key, false);
        case ADMIN_CMD_ADD_USER: // add-user
            if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", fd);
                return ERROR_CLIENT;
            }
        return ADMIN_ADD_USER_READ;
        case ADMIN_CMD_REMOVE_USER: // remove-user
            if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", fd);
                return ERROR_CLIENT;
            }
        return ADMIN_REMOVE_USER_READ;
        case ADMIN_CMD_MAKE_ADMIN: // make-admin
            if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", fd);
                return ERROR_CLIENT;
            }
        return ADMIN_MAKE_ADMIN_READ;

        default:
            log(ERROR, "Unknown admin config command code: %u", code);
            return CONFIG_DONE;
    }
}


static const struct state_definition states_config[] = {
    [READ_CREDENTIALS] = {
        .state = READ_CREDENTIALS,
        .on_read_ready = handle_auth_config_read,
    },
    [AUTH_DONE] = {
        .state = AUTH_DONE,
        .on_write_ready = handle_auth_config_write,
    },
    [USER_METRICS] = {
        .state = USER_METRICS,
        .on_write_ready = handle_user_metrics_write,
    },
    [ADMIN_INITIAL_REQUEST_READ] = {
        .state = ADMIN_INITIAL_REQUEST_READ,
        .on_read_ready = handle_admin_initial_request_read,
    },
    [ADMIN_INITIAL_REQUEST_WRITE] = {
        .state = ADMIN_INITIAL_REQUEST_WRITE,
        .on_write_ready = handle_admin_initial_request_write,
    },

    [ADMIN_METRICS_SEND] = {
        .state = ADMIN_METRICS_SEND,
        .on_write_ready = handle_admin_metrics_write,  // o handleAdminScopeWrite si es user
    },
    [ADMIN_COMMAND_READ] = {
        .state = ADMIN_COMMAND_READ,
        .on_read_ready = handle_admin_config_read,
    },
    [ADMIN_BUFFER_SIZE_CHANGE] = {
        .state = ADMIN_BUFFER_SIZE_CHANGE,
        .on_write_ready = handle_admin_buffer_size_change_write,
    },
    [ADMIN_BUFFER_SIZE_CHANGE_READ] = {
        .state = ADMIN_BUFFER_SIZE_CHANGE_READ,
        .on_read_ready = handle_admin_buffer_size_change_read,
    },
    [ADMIN_ACCEPTS_NO_AUTH] = {
        .state = ADMIN_ACCEPTS_NO_AUTH,
        .on_write_ready = handle_admin_accepts_no_auth_write,
    },
    [ADMIN_REJECTS_NO_AUTH] = {
        .state = ADMIN_REJECTS_NO_AUTH,
        .on_write_ready = handle_admin_rejects_no_auth_write,
    },
    [ADMIN_ADD_USER] = {
        .state = ADMIN_ADD_USER,
        .on_write_ready = handle_admin_add_user_write,
    },
    [ADMIN_ADD_USER_READ] = {
        .state = ADMIN_ADD_USER_READ,
        .on_read_ready = handle_admin_add_user_read,
    },
    [ADMIN_REMOVE_USER] = {
        .state = ADMIN_REMOVE_USER,
        .on_write_ready = handle_admin_remove_user_write,
    },
    [ADMIN_REMOVE_USER_READ] = {
        .state = ADMIN_REMOVE_USER_READ,
        .on_read_ready = handle_admin_remove_user_read,
    },
    [ADMIN_MAKE_ADMIN] = {
        .state = ADMIN_MAKE_ADMIN,
        .on_write_ready = handle_admin_make_admin_write,
    },    [ADMIN_MAKE_ADMIN_READ] = {
        .state = ADMIN_MAKE_ADMIN_READ,
        .on_read_ready = handle_admin_make_admin_read,
    },
    [SEND_FAILURE_RESPONSE] = {
        .state = SEND_FAILURE_RESPONSE,
        .on_write_ready = send_metrics_fail_response,
    },
    [CONFIG_DONE] = {
        .state = CONFIG_DONE,
        .on_arrival = handle_config_done,
    },
    [AUTH_FAIL] = {
        .state = AUTH_FAIL,
        .on_write_ready = send_auth_fail,
    },
    [BAD_REQUEST_ERROR] = {
        .state = BAD_REQUEST_ERROR,
        .on_write_ready = send_bad_request,
    },
    [ERROR_CONFIG_CLIENT] = {
        .state = ERROR_CONFIG_CLIENT,
        .on_arrival = handle_config_done,
    }
};


int initialize_client_config_data(client_config_data *data) {
    struct state_machine *stm = malloc(sizeof(struct state_machine));
    if (stm == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    stm->initial = READ_CREDENTIALS;
    stm->states = states_config;
    stm->max_state = ERROR_CONFIG_CLIENT;
    stm_init(stm);

    buffer *buf = malloc(sizeof(buffer));
    if (buf == NULL) {
        free(stm);
        return -1;
    }
    buf->data = malloc(buffer_size);
    if (buf->data == NULL) {
        free(buf);
        free(stm);
        return -1;
    }
    buffer_init(buf, buffer_size, buf->data);
    data->client_buffer = buf;
    data->stm = stm;
    data->state = READ_CREDENTIALS;
    data->bytes_read = 0;
    data->userlen = 0;
    data->passlen = 0;
    data->role = ROLE_INVALID;

    memset(data->auth_info.username, 0, sizeof(data->auth_info.username));
    memset(data->auth_info.password, 0, sizeof(data->auth_info.password));
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);

    return 0;
}

void handle_config_timeout(struct selector_key *key) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    const client_config_data *data = key->data;

    if (difftime(now.tv_sec, data->last_activity.tv_sec) > CONFIG_TIMEOUT_SEC ) {
        selector_unregister_fd(key->s, key->fd);
    }
}

static const fd_handler client_handler = {
    .handle_read = config_read,
    .handle_write = config_write,
    .handle_close = handle_config_close,
    .handle_timeout = handle_config_timeout,
};

void config_read(struct selector_key *key) {
    client_config_data *data = key->data;
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);
    stm_handler_read(data->stm, key); //usar enum para detectar errores
}

void config_write(struct selector_key *key) {
    client_config_data *data = key->data;
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);
    stm_handler_write(data->stm, key);
}

void handle_server_config_close(struct selector_key *key) {
    for (size_t i = 0; i < MAX_USERS; i++) {
        if (socks_args->users[i].is_added) {
            free(socks_args->users[i].name);
            socks_args->users[i].name = NULL;
        }
        if (socks_args->users[i].is_added) {
            free(socks_args->users[i].pass);
            socks_args->users[i].pass = NULL;
        }
    }
    free_user_metrics_table();
    close(key->fd);
}

void handle_config_close(struct selector_key *key) {
    client_config_data *data = key->data;
    if (data) {
        if (data->client_buffer) {
            free(data->client_buffer->data);
            free(data->client_buffer);
        }
        if (data->stm) {
            free(data->stm);
        }
        free(data);
    }
    close(key->fd);
}

void handle_config_read(struct selector_key *key) {
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);
    const int new_socket = attempt_tcp_config_connection(key->fd);
    if (new_socket < 0) return;

    if (selector_fd_set_nio(new_socket) == -1) {
        close(new_socket);
        return;
    }

    getpeername(new_socket, (struct sockaddr*)&address, &addr_len);

    client_config_data *data = calloc(1, sizeof(client_config_data));
    if (!data) {
        close(new_socket);
        return;
    }
    if (initialize_client_config_data(data) < 0) {
        close(new_socket);
        free(data);
        return;
    }


    if (selector_register(key->s, new_socket, &client_handler, OP_READ, data) != SELECTOR_SUCCESS) {
        handle_config_close(&(struct selector_key){.fd = new_socket, .data = data});
        return;
    }

}

int attempt_tcp_config_connection(const int serv_sock) {
    struct sockaddr_storage clnt_addr;
    socklen_t clnt_addr_len = sizeof(clnt_addr);
    const int clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_len);
    if (clnt_sock < 0) {
        log(ERROR, "accept() failed");
        return -1;
    }
    print_socket_address((struct sockaddr *)&clnt_addr, addr_buffer);
    return clnt_sock;
}



