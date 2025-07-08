#include "tcpServerConfigUtil.h"
#include "../utils/logger.h"
#include "../utils/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "rbt.h"
#include "../metrics/metrics.h"
#include "utils/user_metrics_table.h"
#include "server.h"

#include "args.h"

#define MAX_ADDR_BUFFER 128
#define METRICS_BUF_CHUNK 4096


#define CONFIG_VERSION 0x01
#define STATUS_OK 0x00
#define STATUS_FAIL 0x01
#define ROLE_USER 0x00
#define ROLE_ADMIN 0x01
#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64



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
    if (available < 3) return READ_CREDENTIALS;

    uint8_t version = ptr[0];
    if (version != CONFIG_VERSION) {
        log(ERROR, "Unsupported MAEP version: %u", version);
        return CONFIG_DONE;
    }
    uint8_t reserved = ptr[1];
    uint8_t userlen = ptr[2];

    // Se necesitan los bytes del username y al menos 1 byte para passlen
    if (available < 3 + userlen + 1) return READ_CREDENTIALS;

    char username[MAX_USERNAME_LEN + 1] = {0};
    memcpy(username, ptr + 3, userlen);
    username[userlen] = '\0';

    uint8_t passlen = ptr[3 + userlen];

    // Se necesitan los bytes del password
    if (available < 3 + userlen + 1 + passlen) return READ_CREDENTIALS;

    char password[MAX_PASSWORD_LEN + 1] = {0};
    memcpy(password, ptr + 3 + userlen + 1, passlen);
    password[passlen] = '\0';

    // Avanzar el buffer
    buffer_read_adv(data->clientBuffer, 3 + userlen + 1 + passlen);

    strncpy(data->authInfo.username, username, MAX_USERNAME_LEN);
    strncpy(data->authInfo.password, password, MAX_PASSWORD_LEN);

    log(INFO, "Received username: %s", data->authInfo.username);
    log(INFO, "Received password: %s", data->authInfo.password);

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
    int clntSocket = key->fd;
    clientConfigData *data = key->data;

    uint8_t response[4] = { CONFIG_VERSION, RSV, STATUS_FAIL, ROLE_USER };
    if (data->role == ROLE_ADMIN) {
        response[2] = STATUS_OK;
        response[3] = ROLE_ADMIN;
    } else if (data->role == ROLE_USER) {
        response[2] = STATUS_OK;
        response[3] = ROLE_USER;
    }

    const ssize_t sent = send(clntSocket, response, sizeof(response), MSG_DONTWAIT);
    if (sent < 0) {
        log(ERROR, "send() failed on client socket %d", clntSocket);
        return CONFIG_DONE;
    }

    if (data->role == ROLE_INVALID) {
        log(ERROR, "Authentication failed for client socket %d", clntSocket);
        return CONFIG_DONE;
    }

    log(INFO, "Authenticated client %s as %s", data->authInfo.username,
        data->role == ROLE_ADMIN ? "ADMIN" : "USER");

    if (data->role != ROLE_ADMIN) {
        selector_set_interest_key(key, OP_WRITE);
        return USER_METRICS;
    }
    selector_set_interest_key(key, OP_READ);
    return ADMIN_INITIAL_REQUEST_READ;
}

unsigned handleUserMetricsWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    int clntSocket = key->fd;

    if (data->metrics_buf == NULL) {
        size_t bufsize = METRICS_BUF_CHUNK;
        char *buffer = malloc(bufsize);
        if (!buffer) {
            uint8_t response[3] = { CONFIG_VERSION, 0x00, 0x01 };
            send(clntSocket, response, sizeof(response), MSG_DONTWAIT);
            return CONFIG_DONE;
        }

        FILE *memfile = fmemopen(buffer, bufsize, "w");
        if (!memfile) {
            free(buffer);
            uint8_t response[3] = { CONFIG_VERSION, 0x00, 0x01 };
            send(clntSocket, response, sizeof(response), MSG_DONTWAIT);
            return CONFIG_DONE;
        }

        user_metrics *um = get_or_create_user_metrics(data->authInfo.username);
        if (!um) {
            log(ERROR, "User metrics not found for %s", data->authInfo.username);
            fclose(memfile);
            free(buffer);
            uint8_t response[3] = { CONFIG_VERSION, 0x00, 0x01 };
            send(clntSocket, response, sizeof(response), MSG_DONTWAIT);
            return CONFIG_DONE;
        }

        print_user_metrics_tabbed(um, data->authInfo.username, memfile);
        fflush(memfile);

        size_t written = ftell(memfile);
        fclose(memfile);

        // Header (3) + longitud (4) + cuerpo
        size_t total_len = 3 + 4 + written;
        char *full_buf = malloc(total_len);
        if (!full_buf) {
            free(buffer);
            uint8_t response[3] = { CONFIG_VERSION, 0x00, 0x01 };
            send(clntSocket, response, sizeof(response), MSG_DONTWAIT);
            return CONFIG_DONE;
        }

        // Header
        full_buf[0] = CONFIG_VERSION;
        full_buf[1] = 0x00;
        full_buf[2] = 0x00;

        // Longitud en network byte order
        uint32_t body_len = htonl(written);
        memcpy(full_buf + 3, &body_len, 4);

        // Cuerpo
        memcpy(full_buf + 7, buffer, written);

        free(buffer);

        data->metrics_buf = full_buf;
        data->metrics_buf_len = total_len;
        data->metrics_buf_offset = 0;
    }

    const size_t to_send = data->metrics_buf_len - data->metrics_buf_offset;
    const ssize_t sent = send(clntSocket, data->metrics_buf + data->metrics_buf_offset, to_send, MSG_DONTWAIT);
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
    int clntSocket = key->fd;

    if (data->target_ulen == 0) {
        if (data->metrics_buf == NULL) {
            size_t bufsize = METRICS_BUF_CHUNK;
            char *buffer = malloc(bufsize);
            if (!buffer) return CONFIG_DONE;

            FILE *memfile = fmemopen(buffer, bufsize, "w");
            if (!memfile) {
                free(buffer);
                return CONFIG_DONE;
            }

            print_global_metrics(memfile);
            fflush(memfile);

            const size_t written = ftell(memfile);
            fclose(memfile);

            // Header (3) + longitud (4) + cuerpo
            size_t total_len = 3 + 4 + written;
            char *full_buf = malloc(total_len);
            if (!full_buf) {
                free(buffer);
                return CONFIG_DONE;
            }

            full_buf[0] = CONFIG_VERSION;
            full_buf[1] = 0x00;
            full_buf[2] = 0x00;
            uint32_t body_len = htonl(written);
            memcpy(full_buf + 3, &body_len, 4);
            memcpy(full_buf + 7, buffer, written);

            free(buffer);

            data->metrics_buf = full_buf;
            data->metrics_buf_len = total_len;
            data->metrics_buf_offset = 0;
        }

        const size_t to_send = data->metrics_buf_len - data->metrics_buf_offset;
        const ssize_t sent = send(clntSocket, data->metrics_buf + data->metrics_buf_offset, to_send, MSG_DONTWAIT);
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
    log(INFO, "Fetching metrics for user: %s", data->target_username);
    user_metrics *um = get_or_create_user_metrics(data->target_username);
    if (!um) {
        log(ERROR, "User metrics not found for %s", data->target_username);
        return CONFIG_DONE;
    }
    if (data->metrics_buf == NULL) {
        size_t bufsize = METRICS_BUF_CHUNK;
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
        const size_t total_len = 3 + 4 + written;
        char *full_buf = malloc(total_len);
        if (!full_buf) {
            free(buffer);
            return CONFIG_DONE;
        }

        // Header
        full_buf[0] = CONFIG_VERSION;
        full_buf[1] = 0x00; // RSV
        full_buf[2] = 0x00; // STATUS_OK

        // Longitud en network byte order
        const uint32_t body_len = htonl(written);
        memcpy(full_buf + 3, &body_len, 4);

        // Cuerpo
        memcpy(full_buf + 7, buffer, written);

        free(buffer);

        data->metrics_buf = full_buf;
        data->metrics_buf_len = total_len;
        data->metrics_buf_offset = 0;
    }
    const size_t to_send = data->metrics_buf_len - data->metrics_buf_offset;
    const ssize_t sent = send(clntSocket, data->metrics_buf + data->metrics_buf_offset, to_send, MSG_DONTWAIT);
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
    const uint8_t *ptr = buffer_write_ptr(data->clientBuffer, &available);
    const ssize_t numBytesRcvd = recv(fd, ptr, available, MSG_DONTWAIT);
    if (numBytesRcvd <= 0) {
        if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", fd);
    } else {
        log(ERROR, "recv() failed on client socket %d: %s", fd, strerror(errno));
    }
        return CONFIG_DONE;
    }
    log(INFO, "Handling admin initial request read on fd %d", fd);
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
    if (rsv != 0x00) {
        log(ERROR, "Invalid reserved byte in admin request: %u", rsv);
        return CONFIG_DONE;
    }
    log(INFO, "Admin command: %u, username length: %u", cmd, ulen);

    if (numBytesRcvd < 4 + ulen) return ADMIN_INITIAL_REQUEST_READ;

    char username[MAX_USERNAME_LEN + 1] = {0};
    if (ulen > 0) memcpy(username,  buffer_read_ptr(data->clientBuffer, &available), ulen);
    data->target_ulen = ulen;

    // Save info in clientData
    data->admin_cmd = cmd;
    strncpy(data->target_username, username, ulen);
    log(INFO, "target_username: %s", data->target_username);

    selector_set_interest_key(key, OP_WRITE);
    return ADMIN_INITIAL_REQUEST_WRITE;
}


unsigned handleAdminInitialRequestWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    const int fd = key->fd;

    uint8_t response[3] = {CONFIG_VERSION, 0x00, 0x00};

    if (data->admin_cmd == 0) { // STATS
        response[2] = 0x00;
        send(fd, response, sizeof(response), MSG_DONTWAIT);
        selector_set_interest_key(key, OP_WRITE);
        return ADMIN_METRICS_SEND;
    }
    if (data->admin_cmd == 1) { // CONFIG
        response[2] = 0x01;
        send(fd, response, sizeof(response), MSG_DONTWAIT);
        selector_set_interest_key(key, OP_READ);
        return ADMIN_COMMAND_READ;
    }
    response[2] = 0xFF;
    send(fd, response, sizeof(response), MSG_DONTWAIT);
    return CONFIG_DONE;
}

unsigned handleAdminConfigRead(struct selector_key *key) {
    clientConfigData *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->clientBuffer, &available);

    const ssize_t numBytesRcvd = recv(fd, ptr, (available < 3) ? available : 3, 0);
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
    if (rsv != 0x00) {
        log(ERROR, "Invalid reserved byte in admin config request: %u", rsv);
        return CONFIG_DONE;
    }
    const uint8_t code = buffer_read(data->clientBuffer);
    if (code < 0x00 || code > 0x05) {
        log(ERROR, "Invalid admin config command code: %u", code);
        return CONFIG_DONE;
    }
    // data->admin_cmd =code;
    // if (data->admin_cmd < 0x00 || data->admin_cmd > 0x01) {
    //     log(ERROR, "Invalid admin command: %u", data->admin_cmd);
    //     return CONFIG_DONE;
    // }


    switch (code) {
        case 0x00: // change buffer size
            selector_set_interest_key(key, OP_WRITE);
            return ADMIN_BUFFER_SIZE_CHANGE;

        case 0x01: // accepts-no-auth
            selector_set_interest_key(key, OP_WRITE);
            return ADMIN_ACCEPTS_NO_AUTH;

        case 0x02: // not-accepts-no-auth
            selector_set_interest_key(key, OP_WRITE);
            return ADMIN_REJECTS_NO_AUTH;

        case 0x03: // add-user
            selector_set_interest_key(key, OP_READ);
            return ADMIN_ADD_USER_READ;
        case 0x04: // remove-user
            selector_set_interest_key(key, OP_READ);
            log(INFO, "handling remove user");
            return ADMIN_REMOVE_USER_READ;
        case 0x05: // make-admin
            selector_set_interest_key(key, OP_READ);
            return ADMIN_MAKE_ADMIN_READ;

        default:
            log(ERROR, "Unknown admin config command code: %u", code);
            return CONFIG_DONE;
    }
}

unsigned handleAdminBufferSizeChangeWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    const int fd = key->fd;

    size_t available;
    uint8_t *ptr = buffer_read_ptr(data->clientBuffer, &available);
    if (available < 6) return ADMIN_BUFFER_SIZE_CHANGE;

    uint32_t new_buf_size = ntohl(*(uint32_t *)(ptr + 2)); // salteamos VERSION, RSV

    if (new_buf_size < 1024 || new_buf_size > 65536) {
        log(ERROR, "Invalid buffer size: %u", new_buf_size);
        uint8_t response[6] = { CONFIG_VERSION, 0x00, 0x01, 0x00, 0x00, 0x00 };  // 0x00 = código de cambio de buffer
        send(fd, response, sizeof(response), MSG_DONTWAIT);
        return CONFIG_DONE;
    }


    buffer_read_adv(data->clientBuffer, 6);

    bufferSize = new_buf_size;

    uint8_t response[6] = { CONFIG_VERSION, 0x00, 0x00, 0x00, 0x00, 0x00 };
    send(fd, response, sizeof(response), MSG_DONTWAIT);

    return CONFIG_DONE;
}

unsigned handleAdminAcceptsNoAuthWrite(struct selector_key *key) {
    serverAcceptsNoAuth = true;

    uint8_t response[4] = { CONFIG_VERSION, RSV, 0x01, 0x00 };
    send(key->fd, response, sizeof(response), MSG_DONTWAIT);

    return CONFIG_DONE;
}

unsigned handleAdminRejectsNoAuthWrite(struct selector_key *key) {
    serverAcceptsNoAuth = false;

    uint8_t response[4] = { CONFIG_VERSION, RSV, 0x02, 0x00 };
    send(key->fd, response, sizeof(response), MSG_DONTWAIT);

    return CONFIG_DONE;
}

unsigned addUser( char * username, const uint8_t ulen,  char *password, const uint8_t passlen, const bool is_admin) {
    if (socksArgs == NULL || socksArgs->users == NULL) {
        log(ERROR, "socksArgs or users array is NULL");
        return false;
    }

    for (size_t i = 0; i < MAX_USERS; i++) {
        if ( socksArgs->users[i].name != NULL &&
            strncmp(socksArgs->users[i].name, username, ulen) == 0) {
            log(ERROR, "User %s already exists", username);
            return false; // User already exists
        }
        if (socksArgs->users[i].name == NULL) {
            // Found an empty slot
            socksArgs->users[i].name = malloc(ulen + 1);
            socksArgs->users[i].pass = malloc(passlen + 1);
            if (socksArgs->users[i].name == NULL || socksArgs->users[i].pass == NULL) {
                log(ERROR, "Memory allocation failed for new user");
                return false;
            }
            strncpy(socksArgs->users[i].name, username, ulen);
            strncpy(socksArgs->users[i].pass, password, passlen);
            socksArgs->users[i].name[ulen] = '\0'; // Initialize to empty string
            socksArgs->users[i].pass[passlen] = '\0'; // Initialize to empty string
            socksArgs->users[i].is_admin = is_admin;
            //TODO: need to free the mallocs. Seems complicated but is not really important for now
            return true;
        }
    }
    log(ERROR, "User limit reached, cannot add more users");
    return false;
}

unsigned handleAdminAddUserRead(struct selector_key * key) {
    clientConfigData *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->clientBuffer, &available);

    const ssize_t numBytesRcvd = recv(fd, ptr, available, 0);
    if (numBytesRcvd <= 0) {
        if (numBytesRcvd == 0) {
            log(INFO, "Client socket %d closed connection", fd);
            return CONFIG_DONE;
        }
        log(ERROR, "recv() failed on client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }

    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    if (numBytesRcvd < 4) return ADMIN_ADD_USER_READ; // versión, rsv, código (1 byte)

    const uint8_t ulen = buffer_read(data->clientBuffer);
    if (ulen > MAX_USERNAME_LEN) {
        log(ERROR, "Username length exceeds maximum: %u", ulen);
        return CONFIG_DONE;
    }
    char username[MAX_USERNAME_LEN + 1] = {0};
    if (ulen > 0) memcpy(username,    buffer_read_ptr(data->clientBuffer, &available),  ulen);

    buffer_read_adv(data->clientBuffer, ulen);

    const uint8_t passlen = buffer_read(data->clientBuffer);
    if (passlen > MAX_PASSWORD_LEN) {
        log(ERROR, "Password length exceeds maximum: %u", passlen);
        return CONFIG_DONE;
    }
    char password[MAX_PASSWORD_LEN + 1] = {0};

    if (passlen > 0) memcpy(password, buffer_read_ptr(data->clientBuffer, &available) ,passlen);
    buffer_read_adv(data->clientBuffer, passlen);
    int flag = 1;

    log(INFO, "received username: %s", username);
    log(INFO, "received password: %s", password);

    if (!addUser(username, ulen, password, passlen,false)) {
        flag = 0;
    }

    buffer_reset(data->clientBuffer);
    buffer_write(data->clientBuffer, flag);
    selector_set_interest_key(key, OP_WRITE);
    return ADMIN_ADD_USER;

}

unsigned handleAdminAddUserWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    int fd = key->fd;
    int flag = buffer_read(data->clientBuffer);

    if (flag) {
    const uint8_t response[4] = { CONFIG_VERSION, RSV, 0x03, 0x00 };
        send(fd, response, sizeof(response), MSG_DONTWAIT);
    } else {
        log(ERROR, "Failed to add user");
    const uint8_t response[4] = { CONFIG_VERSION, RSV, 0x03, 0x01 };
        send(fd, response, sizeof(response), MSG_DONTWAIT);
    }

    return CONFIG_DONE; //TODO: lo hacemos persistnece?
}

int removeUser(char * username, uint8_t ulen) {
        if (socksArgs == NULL || socksArgs->users == NULL) {
        log(ERROR, "socksArgs or users array is NULL");
        return false;
    }

    // Busca el usuario a borrar
    for (size_t i = 0; i < MAX_USERS; i++) {
        if (socksArgs->users[i].name != NULL && strncmp(socksArgs->users[i].name, username, ulen) == 0) {
            // Busca el último usuario válido
            size_t last = MAX_USERS;
            for (size_t j = 0; j < MAX_USERS; j++) {
                if (socksArgs->users[j].name == NULL) {
                    last = j;
                    break;
                }
            }
            if (last == 0) return false; // No hay usuarios

            size_t last_idx = last - 1;
            if (i != last_idx) {
                // Libera el usuario a borrar
                free(socksArgs->users[i].name);
                free(socksArgs->users[i].pass);
                // Copia el último usuario en la posición borrada
                socksArgs->users[i].name = socksArgs->users[last_idx].name;
                socksArgs->users[i].pass = socksArgs->users[last_idx].pass;
                socksArgs->users[i].is_admin = socksArgs->users[last_idx].is_admin;
            } else {
                // Si es el último, solo libera
                free(socksArgs->users[i].name);
                free(socksArgs->users[i].pass);
            }
            // Marca el último como vacío
            socksArgs->users[last_idx].name = NULL;
            socksArgs->users[last_idx].pass = NULL;
            socksArgs->users[last_idx].is_admin = false;
            return true;
        }
    }
    log(ERROR, "User %s not found", username);
    return false;

}

unsigned handleAdminRemoveUserRead(struct selector_key * key) {
    clientConfigData *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->clientBuffer, &available);

    const ssize_t numBytesRcvd = recv(fd, ptr, available, 0);
    if (numBytesRcvd <= 0) {
        if (numBytesRcvd == 0) {
            log(INFO, "Client socket %d closed connection", fd);
            return CONFIG_DONE;
        }
        log(ERROR, "recv() failed on client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }

    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    if (numBytesRcvd < 2) return ADMIN_REMOVE_USER_READ; // versión, rsv, código (1 byte)

    const uint8_t ulen = buffer_read(data->clientBuffer);
    if (ulen > MAX_USERNAME_LEN) {
        log(ERROR, "Username length exceeds maximum: %u", ulen);
        return CONFIG_DONE;
    }
    char username[MAX_USERNAME_LEN + 1] = {0};
    if (ulen > 0) memcpy(username,    buffer_read_ptr(data->clientBuffer, &available),  ulen);

    buffer_read_adv(data->clientBuffer, ulen);

    int flag = 1;

    log(INFO, "received username: %s", username);
    if (!removeUser(username, ulen)) {
        flag = 0;
    }

    buffer_reset(data->clientBuffer);
    buffer_write(data->clientBuffer, flag);
    selector_set_interest_key(key, OP_WRITE);
    return ADMIN_REMOVE_USER;
}

unsigned handleAdminRemoveUserWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    int fd = key->fd;
    int flag = buffer_read(data->clientBuffer);

    if (flag) {
        const uint8_t response[4] = { CONFIG_VERSION, RSV, 0x04, 0x00 };
        send(fd, response, sizeof(response), MSG_DONTWAIT);
    } else {
        log(ERROR, "Failed to remove user");
        const uint8_t response[4] = { CONFIG_VERSION, RSV, 0x04, 0x01 };
        send(fd, response, sizeof(response), MSG_DONTWAIT);
    }

    return CONFIG_DONE; //TODO: lo hacemos persistnece?
}

int makeAdmin(char *username, uint8_t ulen) {
    if (socksArgs == NULL || socksArgs->users == NULL) {
        log(ERROR, "socksArgs o users array es NULL");
        return false;
    }

    for (size_t i = 0; i < MAX_USERS; i++) {
        if (socksArgs->users[i].name != NULL &&
            strncmp(socksArgs->users[i].name, username, ulen) == 0) {
            if (socksArgs->users[i].is_admin) {
                log(ERROR, "El usuario %s ya es admin", username);
                return false;
            }
            socksArgs->users[i].is_admin = true;
            log(INFO, "Usuario %s promovido a admin", username);
            return true;
            }
    }
    log(ERROR, "Usuario %s no encontrado", username);
    return false;
}

unsigned handleAdminMakeAdminRead(struct selector_key * key) {
    clientConfigData *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->clientBuffer, &available);

    const ssize_t numBytesRcvd = recv(fd, ptr, available, 0);
    if (numBytesRcvd <= 0) {
        if (numBytesRcvd == 0) {
            log(INFO, "Client socket %d closed connection", fd);
            return CONFIG_DONE;
        }
        log(ERROR, "recv() failed on client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }

    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    if (numBytesRcvd < 2) return ADMIN_REMOVE_USER_READ; // versión, rsv, código (1 byte)

    const uint8_t ulen = buffer_read(data->clientBuffer);
    if (ulen > MAX_USERNAME_LEN) {
        log(ERROR, "Username length exceeds maximum: %u", ulen);
        return CONFIG_DONE;
    }
    char username[MAX_USERNAME_LEN + 1] = {0};
    if (ulen > 0) memcpy(username,    buffer_read_ptr(data->clientBuffer, &available),  ulen);

    buffer_read_adv(data->clientBuffer, ulen);

    int flag = 1;

    log(INFO, "received username: %s", username);
    if (!makeAdmin(username, ulen)) {
        flag = 0;
    }

    buffer_reset(data->clientBuffer);
    buffer_write(data->clientBuffer, flag);
    selector_set_interest_key(key, OP_WRITE);
    return ADMIN_MAKE_ADMIN;
}

unsigned handleAdminMakeAdminWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    int fd = key->fd;
    int flag = buffer_read(data->clientBuffer);

    if (flag) {
        const uint8_t response[4] = { CONFIG_VERSION, RSV, 0x05, 0x00 };
        send(fd, response, sizeof(response), MSG_DONTWAIT);
    } else {
        log(ERROR, "Failed to make admin user");
        const uint8_t response[4] = { CONFIG_VERSION, RSV, 0x05, 0x01 };
        send(fd, response, sizeof(response), MSG_DONTWAIT);
    }

    return CONFIG_DONE; //TODO: lo hacemos persistnece?
}

unsigned handleAdminMenuRead(struct selector_key *key) {
    clientConfigData *data = key->data;
    int fd = key->fd;
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
    if (rsv != 0x00) {
        log(ERROR, "Invalid reserved byte in admin menu request: %u", rsv);
        return CONFIG_DONE;
    }
    uint8_t cmd = buffer_read(data->clientBuffer);
    if (cmd < 0x00 || cmd > 0x01) {
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

    uint8_t response[3] = {CONFIG_VERSION, 0x00, 0x00};

    if (cmd == 0) { // STATS
        response[2] = 0x00;
        send(fd, response, sizeof(response), MSG_DONTWAIT);
        selector_set_interest_key(key, OP_WRITE);
        return ADMIN_METRICS_SEND;
    }
    if (cmd == 1) { // CONFIG
        response[2] = 0x01;
        send(fd, response, sizeof(response), MSG_DONTWAIT);
        selector_set_interest_key(key, OP_READ);
        return ADMIN_COMMAND_READ;
    }
    response[2] = 0xFF;
    send(fd, response, sizeof(response), MSG_DONTWAIT);
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
    log(INFO, "Initializing state machine");
    stm_init(stm);
    log(INFO, " state machine INITIALIZED");


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
    log(INFO, "Handling client %s", addrBuffer);
    return clntSock;
}



