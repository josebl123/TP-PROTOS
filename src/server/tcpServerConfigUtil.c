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

#include "args.h"

#define MAX_ADDR_BUFFER 128
#define MIN_CONFIG_READ_LENGTH 3 // Minimum bytes to read for config (version, rsv, userlen)
#define METRICS_WRITE_HEADER_SIZE 3 // Size of the metrics header (version, rsv, status, role)
#define METRICS_WRITE_PAYLOAD_LENGTH 4


static char addrBuffer[MAX_ADDR_BUFFER];


unsigned handleAuthConfigRead(struct selector_key *key) {
    int clntSocket = key->fd;
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
        log(ERROR, "Unsupported MAEP version: %u", version);
        return CONFIG_DONE;
    }
    const uint8_t userlen = ptr[2];

    // Se necesitan los bytes del username y al menos 1 byte para passlen
    if (available < MIN_CONFIG_READ_LENGTH + (size_t)userlen + 1) return READ_CREDENTIALS;

    char username[MAX_USERNAME_LEN + 1] = {0};
    memcpy(username, ptr + MIN_CONFIG_READ_LENGTH, userlen);
    username[userlen] = '\0';
    data->userlen = userlen;

    const uint8_t passlen = ptr[MIN_CONFIG_READ_LENGTH + userlen];

    // Se necesitan los bytes del password
    if (available < MIN_CONFIG_READ_LENGTH + (size_t)userlen + 1 + passlen) return READ_CREDENTIALS;

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

    selector_set_interest_key(key, OP_WRITE);
    return AUTH_DONE;
}

unsigned handleAuthConfigWrite(struct selector_key *key) {
    const int clntSocket = key->fd;
    clientConfigData *data = key->data;

    uint8_t response[4] = { CONFIG_VERSION, RSV, STATUS_FAIL, ROLE_USER };
    if (data->role == ROLE_ADMIN) {
        response[2] = STATUS_OK;
        response[3] = ROLE_ADMIN;
    } else if (data->role == ROLE_USER) {
        response[2] = STATUS_OK;
        response[3] = ROLE_USER;
    }

    const ssize_t sent = send(clntSocket, response, sizeof(response), 0);
    if (sent < 0) {
        log(ERROR, "send() failed on client socket %d", clntSocket);
        return CONFIG_DONE;
    }

    if (data->role == ROLE_INVALID) {
        log(ERROR, "Authentication failed for client socket %d", clntSocket);
        return CONFIG_DONE;
    }


    if (data->role != ROLE_ADMIN) {
        selector_set_interest_key(key, OP_WRITE);
        return USER_METRICS;
    }
    selector_set_interest_key(key, OP_READ);
    return ADMIN_INITIAL_REQUEST_READ;
}

unsigned handleUserMetricsWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    const int clntSocket = key->fd;

    if (data->metrics_buf == NULL) {
        const size_t bufsize = METRICS_BUF_CHUNK;
        char *buffer = malloc(bufsize);
        if (!buffer) {
            const uint8_t response[3] = { CONFIG_VERSION, RSV, STATUS_FAIL };
            send(clntSocket, response, sizeof(response), 0);
            return CONFIG_DONE;
        }

        FILE *memfile = fmemopen(buffer, bufsize, "w");
        if (!memfile) {
            free(buffer);
            const uint8_t response[3] = { CONFIG_VERSION, RSV, STATUS_FAIL };
            send(clntSocket, response, sizeof(response), 0);
            return CONFIG_DONE;
        }

        user_metrics *um = get_or_create_user_metrics(data->authInfo.username);
        if (!um) {
            log(ERROR, "User metrics not found for %s", data->authInfo.username);
            fclose(memfile);
            free(buffer);
            const uint8_t response[3] = { CONFIG_VERSION, RSV, STATUS_FAIL };
            send(clntSocket, response, sizeof(response), 0);
            return CONFIG_DONE;
        }

        print_user_metrics_tabbed(um, data->authInfo.username, memfile);
        fflush(memfile);

        const size_t written = ftell(memfile);
        fclose(memfile);

        // Header (3) + longitud (4) + cuerpo
        const size_t total_len = METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH + written;
        char *full_buf = malloc(total_len);
        if (!full_buf) {
            free(buffer);
            const uint8_t response[3] = { CONFIG_VERSION, RSV, STATUS_FAIL };
            send(clntSocket, response, sizeof(response), 0);
            return CONFIG_DONE;
        }

        // Header
        full_buf[0] = CONFIG_VERSION;
        full_buf[1] = RSV;
        full_buf[2] = STATUS_OK;

        // Longitud en network byte order
        const uint32_t body_len = htonl(written);
        memcpy(full_buf + METRICS_WRITE_HEADER_SIZE, &body_len, METRICS_WRITE_PAYLOAD_LENGTH);

        // Cuerpo
        memcpy(full_buf + METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH, buffer, written);

        free(buffer);

        data->metrics_buf = full_buf;
        data->metrics_buf_len = total_len;
        data->metrics_buf_offset = 0;
    }

    const size_t to_send = data->metrics_buf_len - data->metrics_buf_offset;
    const ssize_t sent = send(clntSocket, data->metrics_buf + data->metrics_buf_offset, to_send, 0);
    if (sent < 0) {
        free(data->metrics_buf);
        data->metrics_buf = NULL;
        data->metrics_buf_len = 0;
        data->metrics_buf_offset = 0;
        return CONFIG_DONE;
    }

    data->metrics_buf_offset += sent;

    if (data->metrics_buf_offset >= data->metrics_buf_len) {
        free(data->metrics_buf);
        data->metrics_buf = NULL;
        data->metrics_buf_len = 0;
        data->metrics_buf_offset = 0;
        return CONFIG_DONE;
    }

    return USER_METRICS;
}

void handleConfigDone(const unsigned state, struct selector_key *key) {
    if (state == ERROR_CONFIG_CLIENT) {
        log(ERROR, "Closing remote socket %d due to error", key->fd);
    } else {
        log(INFO, "Closing remote socket %d after completion", key->fd);
    }
    selector_unregister_fd(key->s, key->fd);
}

unsigned handleAdminMetricsWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    const int clntSocket = key->fd;

if (data->target_ulen == 0) {
    if (data->metrics_buf == NULL) {
        const size_t bufsize = METRICS_BUF_CHUNK * (1 + MAX_USERS);
        char *buffer = malloc(bufsize);
        if (!buffer) return CONFIG_DONE;

        FILE *memfile = fmemopen(buffer, bufsize, "w");
        if (!memfile) {
            free(buffer);
            return CONFIG_DONE;
        }

        // Imprime métricas globales
        print_global_metrics(memfile);

        // Imprime métricas de cada usuario
        bool any_connection = false;
        fprintf(memfile, "\n==== ALL USER CONNECTIONS ====\n");
        for (size_t i = 0; i < MAX_USERS; i++) {
            if (socksArgs->users[i].name != NULL) {
                user_metrics *um = get_or_create_user_metrics(socksArgs->users[i].name);
                if (um && um->connections_tree.root != NULL) {
                    print_all_users_metrics_tabbed(um, socksArgs->users[i].name, memfile);
                    any_connection = true;
                }
            }
        }
        if (!any_connection) {
            fprintf(memfile, "\nNO USER CONNECTIONS YET\n\n");
        }
        fprintf(memfile, "\n==== END OF ALL USER CONNECTIONS ====\n\n");
        fflush(memfile);

        const size_t written = ftell(memfile);
        fclose(memfile);

        const size_t total_len = METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH + written;
        char *full_buf = malloc(total_len);
        if (!full_buf) {
            free(buffer);
            return CONFIG_DONE;
        }

        full_buf[0] = CONFIG_VERSION;
        full_buf[1] = RSV;
        full_buf[2] = STATUS_OK;
        const uint32_t body_len = htonl(written);
        memcpy(full_buf + METRICS_WRITE_HEADER_SIZE, &body_len, METRICS_WRITE_PAYLOAD_LENGTH);
        memcpy(full_buf + METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH, buffer, written);

        free(buffer);

        data->metrics_buf = full_buf;
        data->metrics_buf_len = total_len;
        data->metrics_buf_offset = 0;
    }

    const size_t to_send = data->metrics_buf_len - data->metrics_buf_offset;
    const ssize_t sent = send(clntSocket, data->metrics_buf + data->metrics_buf_offset, to_send, 0);
    if (sent < 0) {
        free(data->metrics_buf);
        data->metrics_buf = NULL;
        data->metrics_buf_len = 0;
        data->metrics_buf_offset = 0;
        return CONFIG_DONE;
    }

    data->metrics_buf_offset += sent;

    if (data->metrics_buf_offset >= data->metrics_buf_len) {
        free(data->metrics_buf);
        data->metrics_buf = NULL;
        data->metrics_buf_len = 0;
        data->metrics_buf_offset = 0;

        buffer_reset(data->clientBuffer);
        return CONFIG_DONE;
    }

    return ADMIN_METRICS_SEND;
}

    // Si hay un usuario específico, obtenemos sus métricas
    user_metrics *um = get_or_create_user_metrics(data->target_username);

    if (!um) {
        log(ERROR, "User metrics not found for %s", data->target_username);
        return CONFIG_DONE;
    }
    if (data->metrics_buf == NULL) {
        const size_t bufsize = METRICS_BUF_CHUNK;
        char *buffer = malloc(bufsize);
        if (!buffer) return CONFIG_DONE;

        FILE *memfile = fmemopen(buffer, bufsize, "w");
        if (!memfile) {
            free(buffer);
            return CONFIG_DONE;
        }

        print_user_metrics_tabbed(um, data->target_username, memfile);
        fflush(memfile);

        const size_t written = ftell(memfile);
        fclose(memfile);

        // Header (3) + longitud (4) + cuerpo
        const size_t total_len = METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH + written;
        char *full_buf = malloc(total_len);
        if (!full_buf) {
            free(buffer);
            return CONFIG_DONE;
        }

        // Header
        full_buf[0] = CONFIG_VERSION;
        full_buf[1] = RSV; // RSV
        full_buf[2] = STATUS_OK; // STATUS_OK

        // Longitud en network byte order
        const uint32_t body_len = htonl(written);
        memcpy(full_buf + METRICS_WRITE_HEADER_SIZE, &body_len, METRICS_WRITE_PAYLOAD_LENGTH);

        // Cuerpo
        memcpy(full_buf + METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH , buffer, written);

        free(buffer);

        data->metrics_buf = full_buf;
        data->metrics_buf_len = total_len;
        data->metrics_buf_offset = 0;
    }
    const size_t to_send = data->metrics_buf_len - data->metrics_buf_offset;
    const ssize_t sent = send(clntSocket, data->metrics_buf + data->metrics_buf_offset, to_send, 0);
    if (sent < 0) {
        free(data->metrics_buf);
        data->metrics_buf = NULL;
        data->metrics_buf_len = 0;
        data->metrics_buf_offset = 0;
        return CONFIG_DONE;
    }
    data->metrics_buf_offset += sent;
    if (data->metrics_buf_offset >= data->metrics_buf_len) {
        free(data->metrics_buf);
        data->metrics_buf = NULL;
        data->metrics_buf_len = 0;
        data->metrics_buf_offset = 0;

        buffer_reset(data->clientBuffer); // limpiar buffer para próxima lectura
        return CONFIG_DONE;           // ← volvemos al menú
    }
    return ADMIN_METRICS_SEND; // Continuar enviando métricas
}


unsigned handleAdminInitialRequestRead(struct selector_key *key) {
    clientConfigData *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->clientBuffer, &available);
    const ssize_t numBytesRcvd = recv(fd, ptr, available, 0);
    if (numBytesRcvd <= 0) {
        if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", fd);
    } else {
        log(ERROR, "recv() failed on client socket %d: %s", fd, strerror(errno));
    }
        return CONFIG_DONE;
    }
    buffer_write_adv(data->clientBuffer, numBytesRcvd);
    if (numBytesRcvd < 4) return CONFIG_DONE;
    const uint8_t version = buffer_read(data->clientBuffer);
    const uint8_t rsv = buffer_read(data->clientBuffer);
    const uint8_t cmd = buffer_read(data->clientBuffer); // 0=stats, 1=config
    uint8_t ulen = buffer_read(data->clientBuffer);

    if (version != CONFIG_VERSION) {
        log(ERROR, "Unsupported MAEP version: %u", version);
        return CONFIG_DONE;
    }
    if (rsv != RSV) {
        log(ERROR, "Invalid reserved byte in admin request: %u", rsv);
        return CONFIG_DONE;
    }

    if (numBytesRcvd < 4 + ulen) return ADMIN_INITIAL_REQUEST_READ;

    char username[MAX_USERNAME_LEN + 1] = {0};
    if (ulen > 0) memcpy(username,  buffer_read_ptr(data->clientBuffer, &available), ulen);
    data->target_ulen = ulen;

    // Save info in clientData
    data->admin_cmd = cmd;
    strncpy(data->target_username, username, ulen);

    selector_set_interest_key(key, OP_WRITE);
    return ADMIN_INITIAL_REQUEST_WRITE;
}


unsigned handleAdminInitialRequestWrite(struct selector_key *key) {
    const clientConfigData *data = key->data;
    const int fd = key->fd;

    uint8_t response[3] = {CONFIG_VERSION, RSV, STATUS_OK};

    if (data->admin_cmd == GLOBAL_STATS) { // STATS
        response[2] = GLOBAL_STATS;
        send(fd, response, sizeof(response), 0);
        selector_set_interest_key(key, OP_WRITE);
        return ADMIN_METRICS_SEND;
    }
    if (data->admin_cmd == CONFIG) { // CONFIG
        response[2] = CONFIG;
        send(fd, response, sizeof(response), 0);
        selector_set_interest_key(key, OP_READ);
        return ADMIN_COMMAND_READ;
    }
    response[2] = 0xFF; //status fail pero con 0xff todo:esto lo tenemos definido asi?
    send(fd, response, sizeof(response), 0);
    return CONFIG_DONE;
}

unsigned handleAdminConfigRead(struct selector_key *key) {
    const clientConfigData *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->clientBuffer, &available);

    const ssize_t numBytesRcvd = recv(fd, ptr, available < 3 ? available : 3, 0);
    if (numBytesRcvd <= 0) {
        if (numBytesRcvd == 0) {
            log(INFO, "Client socket %d closed connection", fd);
            return CONFIG_DONE;
        }
        log(ERROR, "recv() failed on client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }

    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    if (numBytesRcvd < 3) return ADMIN_COMMAND_READ; // versión, rsv, código (1 byte)

    const uint8_t version = buffer_read(data->clientBuffer);
    if (version != CONFIG_VERSION) {
        log(ERROR, "Unsupported MAEP version: %u", version);
        return CONFIG_DONE;
    }
    const uint8_t rsv = buffer_read(data->clientBuffer);
    if (rsv != RSV) {
        log(ERROR, "Invalid reserved byte in admin config request: %u", rsv);
        return CONFIG_DONE;
    }
    const uint8_t code = buffer_read(data->clientBuffer);
    if ( code > 0x05) {
        log(ERROR, "Invalid admin config command code: %u", code);
        return CONFIG_DONE;
    }


    switch (code) {
        case ADMIN_CMD_CHANGE_BUFFER_SIZE: // change buffer size
            selector_set_interest_key(key, OP_READ);
            return ADMIN_BUFFER_SIZE_CHANGE_READ;
        case ADMIN_CMD_ACCEPTS_NO_AUTH: // accepts-no-auth
            selector_set_interest_key(key, OP_WRITE);
            return ADMIN_ACCEPTS_NO_AUTH;
        case ADMIN_CMD_REJECTS_NO_AUTH: // not-accepts-no-auth
            selector_set_interest_key(key, OP_WRITE);
            return ADMIN_REJECTS_NO_AUTH;
        case ADMIN_CMD_ADD_USER: // add-user
            selector_set_interest_key(key, OP_READ);
            return ADMIN_ADD_USER_READ;
        case ADMIN_CMD_REMOVE_USER: // remove-user
            selector_set_interest_key(key, OP_READ);
            return ADMIN_REMOVE_USER_READ;
        case ADMIN_CMD_MAKE_ADMIN: // make-admin
            selector_set_interest_key(key, OP_READ);
            return ADMIN_MAKE_ADMIN_READ;

        default:
            log(ERROR, "Unknown admin config command code: %u", code);
            return CONFIG_DONE;
    }
}


unsigned handleAdminMenuRead(struct selector_key *key) {
    clientConfigData *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->clientBuffer, &available);

    ssize_t numBytesRcvd = recv(fd, ptr, available, 0);
    if (numBytesRcvd <= 0) {
        if (numBytesRcvd == 0) {
            log(INFO, "Client socket %d closed connection", fd);
            return CONFIG_DONE;
        }
        log(ERROR, "recv() failed on client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }

    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    if (numBytesRcvd < 4) return ADMIN_MENU_READ;

    const uint8_t version = buffer_read(data->clientBuffer);
    if (version != CONFIG_VERSION) {
        log(ERROR, "Unsupported MAEP version: %u", version);
        return CONFIG_DONE;
    }
    uint8_t rsv = buffer_read(data->clientBuffer);
    if (rsv != RSV) {
        log(ERROR, "Invalid reserved byte in admin menu request: %u", rsv);
        return CONFIG_DONE;
    }
    const uint8_t cmd = buffer_read(data->clientBuffer);
    if ( cmd > 0x01) {
        log(ERROR, "Invalid admin menu command code: %u", cmd);
        return CONFIG_DONE;
    }
    uint8_t ulen = buffer_read(data->clientBuffer);
    if (ulen > MAX_USERNAME_LEN) {
        log(ERROR, "Username length exceeds maximum: %u", ulen);
        return CONFIG_DONE;
    }


    if (numBytesRcvd < 4 + ulen) return ADMIN_MENU_READ;

    char username[MAX_USERNAME_LEN + 1] = {0};
    if (ulen > 0) memcpy(username, ptr + 4, ulen);
    data->target_ulen = ulen;

    // Guardar datos en estructura
    data->admin_cmd = cmd;
    strncpy(data->target_username, username, sizeof(data->target_username));

    selector_set_interest_key(key, OP_WRITE);
    return ADMIN_MENU_WRITE;
}

unsigned handleAdminMenuWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    int fd = key->fd;

    uint8_t response[3] = {CONFIG_VERSION, RSV, STATUS_OK};
    if (data->admin_cmd == 0) { // STATS
        response[2] = GLOBAL_STATS;
        send(fd, response, sizeof(response), 0);
        selector_set_interest_key(key, OP_WRITE);
        return ADMIN_METRICS_SEND;
    }
    if (data->admin_cmd == 1) { // CONFIG
        response[2] = CONFIG;
        send(fd, response, sizeof(response), 0);
        selector_set_interest_key(key, OP_READ);
        return ADMIN_COMMAND_READ;
    }
    response[2] = 0xFF; // Error
    send(fd, response, sizeof(response), 0);
    return CONFIG_DONE;
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
    [ADMIN_MENU_READ] = {
        .state = ADMIN_MENU_READ,
        .on_read_ready = handleAdminMenuRead,
    },
    [ADMIN_MENU_WRITE] = {
        .state = ADMIN_MENU_WRITE,
        .on_write_ready = handleAdminMenuWrite,
    },
    [CONFIG_DONE] = {
        .state = CONFIG_DONE,
        .on_arrival = handleConfigDone,
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
    return 0;
}

static const fd_handler client_handler = {
    .handle_read = config_read,
    .handle_write = config_write,
    .handle_close = handleConfigClose,
};

void config_read(struct selector_key *key) {
    clientConfigData *data = key->data;
    stm_handler_read(data->stm, key); //usar enum para detectar errores
}

void config_write(struct selector_key *key) {
    clientConfigData *data = key->data;
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
    close(key->fd);
}

void handleConfigClose(struct selector_key *key) {
    log(INFO, "Closing client socket %d", key->fd);
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
    int new_socket = acceptTCPConfigConnection(key->fd);
    if (new_socket < 0) return;

    if (selector_fd_set_nio(new_socket) == -1) {
        close(new_socket);
        return;
    }

    getpeername(new_socket, (struct sockaddr*)&address, &addrlen);
    printf("New config connection: fd=%d, ip=%s, port=%d\n",
           new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

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

    printf("Client socket %d registered\n", new_socket);
}

int acceptTCPConfigConnection(const int servSock) {
    struct sockaddr_storage clntAddr;
    socklen_t clntAddrLen = sizeof(clntAddr);
    int clntSock = accept(servSock, (struct sockaddr *)&clntAddr, &clntAddrLen);
    if (clntSock < 0) {
        log(ERROR, "accept() failed");
        return -1;
    }
    printSocketAddress((struct sockaddr *)&clntAddr, addrBuffer);
    return clntSock;
}



