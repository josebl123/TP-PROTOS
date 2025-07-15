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


static char addrBuffer[MAX_ADDR_BUFFER];


unsigned send_bad_request(struct selector_key * key) {
    return genericWrite(key, CONFIG_DONE, BAD_REQUEST_ERROR);
}

unsigned attempt_send_bad_request_error(struct selector_key *key) {
    const clientConfigData *data = key->data;

    buffer_reset(data->clientBuffer);
    buffer_write(data->clientBuffer, CONFIG_VERSION);
    buffer_write(data->clientBuffer, RSV);
    buffer_write(data->clientBuffer,   ERROR );
    buffer_write(data->clientBuffer, ROLE_USER); // status fail
    return send_bad_request(key);
}

unsigned send_auth_fail(struct selector_key *key) {
    const clientConfigData *data = key->data;
    const int clntSocket = key->fd;

    buffer_reset(data->clientBuffer);
    buffer_write(data->clientBuffer, CONFIG_VERSION);
    buffer_write(data->clientBuffer, RSV);
    buffer_write(data->clientBuffer, data->response_code);

    size_t availableBytes;
    const uint8_t *ptr = buffer_read_ptr(data->clientBuffer, &availableBytes);
    const ssize_t sent = send(clntSocket, ptr, availableBytes, 0);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            return BAD_REQUEST_ERROR;
        }
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        return CONFIG_DONE;
    }
    if (sent == 0) {
        return CONFIG_DONE;
    }
    buffer_read_adv(data->clientBuffer, sent); // Avanzar el puntero de lectura del buffer
    return CONFIG_DONE;
}

unsigned handleAuthConfigWrite(struct selector_key *key) {
    const int clntSocket = key->fd;
    const clientConfigData *data = key->data;
    size_t availableBytes;
    const uint8_t *ptr = buffer_read_ptr(data->clientBuffer, &availableBytes);
    const ssize_t sent = send(clntSocket,ptr, availableBytes, 0);

    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            return AUTH_DONE;
        }
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        return CONFIG_DONE;
    }
    if (sent == 0) {
        return CONFIG_DONE;
    }
    buffer_read_adv(data->clientBuffer, sent); // Avanzar el puntero de lectura del buffer
    if (sent < (ssize_t)availableBytes) {
        return AUTH_DONE; // Partial send, wait for next write
    }

    if (data->role == ROLE_INVALID) {
        log(ERROR, "Authentication failed for client socket %d", clntSocket);
        return send_auth_fail(key);
    }

    if (data->role != ROLE_ADMIN) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {;
            log(ERROR, "Failed to set interest for client socket %d", clntSocket);
            return ERROR_CLIENT;
        }
        return attemptUserMetricsWrite(key);
    }
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", clntSocket);
        return ERROR_CLIENT;
    }
    return ADMIN_INITIAL_REQUEST_READ;
}

unsigned attemptAuthConfigWrite (struct selector_key *key) {
    clientConfigData *data = key->data;

    buffer_reset(data->clientBuffer);
    buffer_write(data->clientBuffer, CONFIG_VERSION);
    buffer_write(data->clientBuffer, RSV);
    data->response_code = (data->role != ROLE_INVALID ? STATUS_OK : STATUS_BAD_REQUEST);
    buffer_write(data->clientBuffer, data->response_code);
    if (data->role != ROLE_INVALID) {
        buffer_write(data->clientBuffer, data->role);
    }
    return handleAuthConfigWrite(key);
}

unsigned handleAuthConfigRead(struct selector_key *key) {
    const int clntSocket = key->fd;
    clientConfigData *data = key->data;
    size_t writeLimit;

    uint8_t *readPtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, readPtr, writeLimit, 0);

    if (numBytesRcvd <= 0) {
        log(numBytesRcvd == 0 ? INFO : ERROR, "recv() failed or closed on client socket %d", clntSocket);
        return CONFIG_DONE;
    }

    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    size_t available;
    const uint8_t *ptr = buffer_read_ptr(data->clientBuffer, &available);

    // Se necesitan al menos 3 bytes para version, rsv, userlen
    if (available < MIN_CONFIG_READ_LENGTH) return READ_CREDENTIALS;

    const uint8_t version = ptr[0];
    if (version != CONFIG_VERSION) {
        if (selector_set_interest_key(key, OP_WRITE)!= SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clntSocket);
            return ERROR_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }
    const uint8_t rsv = ptr[1];
    if (rsv != RSV) {
        if (selector_set_interest_key(key, OP_WRITE)!= SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clntSocket);
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
    buffer_read_adv(data->clientBuffer, MIN_CONFIG_READ_LENGTH + userlen + 1 + passlen);

    strncpy(data->authInfo.username, username, MAX_USERNAME_LEN);
    strncpy(data->authInfo.password, password, MAX_PASSWORD_LEN);


    if (socksArgs == NULL) { log(ERROR, "socksArgs is NULL"); return CONFIG_DONE; }

    bool found = false;
    for (size_t i = 0; socksArgs->users[i].name != NULL && i < MAX_USERS; i++) {
        if (strncmp(socksArgs->users[i].name, data->authInfo.username, MAX_USERNAME_LEN) == 0 &&
            strncmp(socksArgs->users[i].pass, data->authInfo.password, MAX_PASSWORD_LEN) == 0) {
            found = true;
            data->role = socksArgs->users[i].is_admin ? ROLE_ADMIN : ROLE_USER;
            break;
        }
    }
    if (!found) {
        data->role = ROLE_INVALID;
    }

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", clntSocket);
        return ERROR_CLIENT;
    }

    return attemptAuthConfigWrite(key);
}



void handleConfigDone(const unsigned state, struct selector_key *key) {
    if (state == ERROR_CONFIG_CLIENT) {
        log(ERROR, "Closing remote socket %d due to error", key->fd);
    }
    selector_unregister_fd(key->s, key->fd);
}

unsigned handleAdminInitialRequestWrite(struct selector_key *key) {
    const int clntSocket = key->fd;
    const clientConfigData *data = key->data;
    size_t availableBytes;
    const uint8_t *ptr = buffer_read_ptr(data->clientBuffer, &availableBytes);
    const ssize_t sent = send(clntSocket,ptr, availableBytes, 0);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            return ADMIN_INITIAL_REQUEST_WRITE;
        }
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        return CONFIG_DONE;
    }
    if (sent == 0) {
        return CONFIG_DONE;
    }
    buffer_read_adv(data->clientBuffer, sent); // Avanzar el puntero de lectura del buffer
    if (sent < (ssize_t)availableBytes) {
        return ADMIN_INITIAL_REQUEST_WRITE; // Partial send, wait for next write
    }


    if (data->admin_cmd == GLOBAL_STATS) { // STATS
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clntSocket);
            return ERROR_CLIENT;
        }
        return attemptAdminMetricsWrite(key);
    }
    if (data->admin_cmd == CONFIG) { // CONFIG
        if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clntSocket);
            return ERROR_CLIENT;
        }
        return ADMIN_COMMAND_READ;
    }
    return CONFIG_DONE;
}


unsigned adminAttemptInitialRequestWrite(struct selector_key *key) {
    const clientConfigData *data = key->data;
    buffer_reset(data->clientBuffer);
    buffer_write(data->clientBuffer, CONFIG_VERSION);
    buffer_write(data->clientBuffer, RSV);
    if (data->admin_cmd == GLOBAL_STATS) {
        buffer_write(data->clientBuffer, GLOBAL_STATS);
    } else if (data->admin_cmd == CONFIG) {
        buffer_write(data->clientBuffer, CONFIG);
    } else {
        buffer_write(data->clientBuffer, 0xFF); // status fail
    }

    return handleAdminInitialRequestWrite(key);
}

unsigned handleAdminInitialRequestRead(struct selector_key *key) {
    clientConfigData *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->clientBuffer, &available);
    const ssize_t numBytesRcvd = recv(fd, ptr, available, 0);
    if (numBytesRcvd <= 0) {
        if (numBytesRcvd == 0) {
    } else {
        log(ERROR, "recv() failed on client socket %d: %s", fd, strerror(errno));
    }
        return CONFIG_DONE;
    }
    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    size_t readAvailable;
    const uint8_t *readPtr = buffer_read_ptr(data->clientBuffer, &readAvailable);
    if (readAvailable < 4) return ADMIN_INITIAL_REQUEST_READ;
    const uint8_t version = readPtr[0];
    const uint8_t rsv = readPtr[1];
    const uint8_t cmd = readPtr[2]; // 0=stats, 1=config
    const uint8_t ulen = readPtr[3];

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

    if (readAvailable < 4 + (size_t)ulen) return ADMIN_INITIAL_REQUEST_READ;
    buffer_read_adv(data->clientBuffer, 4);

    char username[MAX_USERNAME_LEN + 1] = {0};
    if (ulen > 0) memcpy(username,  buffer_read_ptr(data->clientBuffer, &available), ulen);
    data->target_ulen = ulen;

    // Save info in clientData
    data->admin_cmd = cmd;
    strncpy(data->target_username, username, ulen);

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", fd);
        return ERROR_CLIENT;
    }
    return adminAttemptInitialRequestWrite(key);
}

unsigned handleAdminConfigRead(struct selector_key *key) {
    const clientConfigData *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->clientBuffer, &available);

    const ssize_t numBytesRcvd = recv(fd, ptr, available < 3 ? available : 3, 0);
    if (numBytesRcvd <= 0) {
        if (numBytesRcvd == 0) {
            return CONFIG_DONE;
        }
        log(ERROR, "recv() failed on client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }

    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    size_t readAvailable;
    buffer_read_ptr(data->clientBuffer, &readAvailable);

    if (readAvailable < MIN_CONFIG_READ_LENGTH) return ADMIN_COMMAND_READ; // versión, rsv, código (1 byte)

    const uint8_t version = buffer_read(data->clientBuffer);
    if (version != CONFIG_VERSION) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", fd);
            return ERROR_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }
    const uint8_t rsv = buffer_read(data->clientBuffer);
    if (rsv != RSV) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", fd);
            return ERROR_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }
    const uint8_t code = buffer_read(data->clientBuffer);
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
        return attemptAdminAcceptsAuthWrite( key, true);
        case ADMIN_CMD_REJECTS_NO_AUTH: // not-accepts-no-auth
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                log(ERROR, "Failed to set interest for client socket %d", fd);
                return ERROR_CLIENT;
            }
        return attemptAdminAcceptsAuthWrite( key, false);
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
        .on_read_ready = handleAuthConfigRead,
    },
    [AUTH_DONE] = {
        .state = AUTH_DONE,
        .on_write_ready = handleAuthConfigWrite,
    },
    [USER_METRICS] = {
        .state = USER_METRICS,
        .on_write_ready = handleUserMetricsWrite,
    },
    [ADMIN_INITIAL_REQUEST_READ] = {
        .state = ADMIN_INITIAL_REQUEST_READ,
        .on_read_ready = handleAdminInitialRequestRead,
    },
    [ADMIN_INITIAL_REQUEST_WRITE] = {
        .state = ADMIN_INITIAL_REQUEST_WRITE,
        .on_write_ready = handleAdminInitialRequestWrite,
    },

    [ADMIN_METRICS_SEND] = {
        .state = ADMIN_METRICS_SEND,
        .on_write_ready = handleAdminMetricsWrite,  // o handleAdminScopeWrite si es user
    },
    [ADMIN_COMMAND_READ] = {
        .state = ADMIN_COMMAND_READ,
        .on_read_ready = handleAdminConfigRead,
    },
    [ADMIN_BUFFER_SIZE_CHANGE] = {
        .state = ADMIN_BUFFER_SIZE_CHANGE,
        .on_write_ready = handleAdminBufferSizeChangeWrite,
    },
    [ADMIN_BUFFER_SIZE_CHANGE_READ] = {
        .state = ADMIN_BUFFER_SIZE_CHANGE_READ,
        .on_read_ready = handleAdminBufferSizeChangeRead,
    },
    [ADMIN_ACCEPTS_NO_AUTH] = {
        .state = ADMIN_ACCEPTS_NO_AUTH,
        .on_write_ready = handleAdminAcceptsNoAuthWrite,
    },
    [ADMIN_REJECTS_NO_AUTH] = {
        .state = ADMIN_REJECTS_NO_AUTH,
        .on_write_ready = handleAdminRejectsNoAuthWrite,
    },
    [ADMIN_ADD_USER] = {
        .state = ADMIN_ADD_USER,
        .on_write_ready = handleAdminAddUserWrite,
    },
    [ADMIN_ADD_USER_READ] = {
        .state = ADMIN_ADD_USER_READ,
        .on_read_ready = handleAdminAddUserRead,
    },
    [ADMIN_REMOVE_USER] = {
        .state = ADMIN_REMOVE_USER,
        .on_write_ready = handleAdminRemoveUserWrite,
    },
    [ADMIN_REMOVE_USER_READ] = {
        .state = ADMIN_REMOVE_USER_READ,
        .on_read_ready = handleAdminRemoveUserRead,
    },
    [ADMIN_MAKE_ADMIN] = {
        .state = ADMIN_MAKE_ADMIN,
        .on_write_ready = handleAdminMakeAdminWrite,
    },    [ADMIN_MAKE_ADMIN_READ] = {
        .state = ADMIN_MAKE_ADMIN_READ,
        .on_read_ready = handleAdminMakeAdminRead,
    },
    [SEND_FAILURE_RESPONSE] = {
        .state = SEND_FAILURE_RESPONSE,
        .on_write_ready = send_metrics_fail_response,
    },
    [CONFIG_DONE] = {
        .state = CONFIG_DONE,
        .on_arrival = handleConfigDone,
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
        .on_arrival = handleConfigDone,
    }
};


int initializeClientConfigData(clientConfigData *data) {
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
    buf->data = malloc(bufferSize);
    if (buf->data == NULL) {
        free(buf);
        free(stm);
        return -1;
    }
    buffer_init(buf, bufferSize, buf->data);
    data->clientBuffer = buf;
    data->stm = stm;
    data->state = READ_CREDENTIALS;
    data->bytes_read = 0;
    data->userlen = 0;
    data->passlen = 0;
    data->role = ROLE_INVALID;

    memset(data->authInfo.username, 0, sizeof(data->authInfo.username));
    memset(data->authInfo.password, 0, sizeof(data->authInfo.password));
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);

    return 0;
}

void handleConfigTimeout(struct selector_key *key) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    const clientConfigData *data = key->data;

    if (difftime(now.tv_sec, data->last_activity.tv_sec) > CONFIG_TIMEOUT_SEC ) {
        selector_unregister_fd(key->s, key->fd);
    }
}

static const fd_handler client_handler = {
    .handle_read = config_read,
    .handle_write = config_write,
    .handle_close = handleConfigClose,
    .handle_timeout = handleConfigTimeout,
};

void config_read(struct selector_key *key) {
    clientConfigData *data = key->data;
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);
    stm_handler_read(data->stm, key); //usar enum para detectar errores
}

void config_write(struct selector_key *key) {
    clientConfigData *data = key->data;
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);
    stm_handler_write(data->stm, key);
}

void handleServerConfigClose(struct selector_key *key) {
    for (size_t i = 0; i < MAX_USERS; i++) {
        if (socksArgs->users[i].is_added) {
            free(socksArgs->users[i].name);
            socksArgs->users[i].name = NULL;
        }
        if (socksArgs->users[i].is_added) {
            free(socksArgs->users[i].pass);
            socksArgs->users[i].pass = NULL;
        }
    }
    free_user_metrics_table();
    close(key->fd);
}

void handleConfigClose(struct selector_key *key) {
    clientConfigData *data = key->data;
    if (data) {
        if (data->clientBuffer) {
            free(data->clientBuffer->data);
            free(data->clientBuffer);
        }
        if (data->stm) {
            free(data->stm);
        }
        free(data);
    }
    close(key->fd);
}

void handleConfigRead(struct selector_key *key) {
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    const int new_socket = acceptTCPConfigConnection(key->fd);
    if (new_socket < 0) return;

    if (selector_fd_set_nio(new_socket) == -1) {
        close(new_socket);
        return;
    }

    getpeername(new_socket, (struct sockaddr*)&address, &addrlen);

    clientConfigData *data = calloc(1, sizeof(clientConfigData));
    if (!data) {
        close(new_socket);
        return;
    }
    if (initializeClientConfigData(data) < 0) {
        close(new_socket);
        free(data);
        return;
    }


    if (selector_register(key->s, new_socket, &client_handler, OP_READ, data) != SELECTOR_SUCCESS) {
        handleConfigClose(&(struct selector_key){.fd = new_socket, .data = data});
        return;
    }

}

int acceptTCPConfigConnection(const int servSock) {
    struct sockaddr_storage clntAddr;
    socklen_t clntAddrLen = sizeof(clntAddr);
    const int clntSock = accept(servSock, (struct sockaddr *)&clntAddr, &clntAddrLen);
    if (clntSock < 0) {
        log(ERROR, "accept() failed");
        return -1;
    }
    printSocketAddress((struct sockaddr *)&clntAddr, addrBuffer);
    return clntSock;
}



