//
// Created by nicol on 7/12/2025.
//

#include "serverConfigActions.h"
#include "tcpServerUtil.h"
#include "selector.h"
#include "utils/logger.h"
#include "args.h"
#include "utils/user_metrics_table.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "server.h"
#include "serverConfigTypes.h"

int makeAdmin(char *username, uint8_t ulen) {
    if (socksArgs == NULL) {
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

int removeUser(char * username, uint8_t ulen) {
        if (socksArgs == NULL ) {
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

            const size_t last_idx = last - 1;
            remove_user_metrics(socksArgs->users[i].name);
            if (i != last_idx) {
                // Libera el usuario a borrar
                // free(socksArgs->users[i].name); //fixme:da error si lo descomento y fue declarado originalmente
                // free(socksArgs->users[i].pass);
                // Copia el último usuario en la posición borrada
                if (socksArgs->users[i].is_added) {
                    free(socksArgs->users[i].name);
                    free(socksArgs->users[i].pass);
                }
                socksArgs->users[i].name = socksArgs->users[last_idx].name;
                socksArgs->users[i].pass = socksArgs->users[last_idx].pass;
                socksArgs->users[i].is_admin = socksArgs->users[last_idx].is_admin;
            } else {
                // Si es el último, solo libera
                // free(socksArgs->users[i].name); //fixme:da error si lo descomento y fue declarado originalmente
                // free(socksArgs->users[i].pass);
            }
            // Marca el último como vacío
            socksArgs->users[last_idx].name = NULL;
            socksArgs->users[last_idx].pass = NULL;
            socksArgs->users[last_idx].is_admin = false;
            socksArgs->users[last_idx].is_added = false; // Marca como no agregado
            return true;
        }
    }
    log(ERROR, "User %s not found", username);
    return false;

}

unsigned addUser( char * username, const uint8_t ulen,  char *password, const uint8_t passlen, const bool is_admin) {
    if (socksArgs == NULL ) {
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
            socksArgs->users[i].is_added = true; // Mark as added
            //TODO: need to free the mallocs. Seems complicated but is not really important for now
            return true;
        }
    }
    log(ERROR, "User limit reached, cannot add more users");
    return false;
}
unsigned handleAdminBufferSizeChangeRead(struct selector_key * key) {
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

    if (numBytesRcvd < 5) return ADMIN_BUFFER_SIZE_CHANGE_READ; // versión, rsv, código (1 byte)
    // Saltar los primeros 4 bytes
    buffer_read_adv(data->clientBuffer, 4); //TODO: MAGIC NUMBER

    // Leer el nuevo buffer_size (por ejemplo, como uint32_t en network order)
    const uint32_t new_buf_size = ntohl(*(uint32_t *)buffer_read_ptr(data->clientBuffer, &available));
    log(INFO, "Received new buffer size: %u", new_buf_size);
    int flag = 1;

    if (new_buf_size < 1024 || new_buf_size > 65536) {
        flag = 0;
    }

    bufferSize = new_buf_size;


    buffer_reset(data->clientBuffer);
    buffer_write(data->clientBuffer, flag);
    selector_set_interest_key(key, OP_WRITE);
    return ADMIN_BUFFER_SIZE_CHANGE;
}

unsigned handleAdminBufferSizeChangeWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    int fd = key->fd;
    int flag = buffer_read(data->clientBuffer);

    if (flag) {
        const uint8_t response[4] = { CONFIG_VERSION, RSV, ADMIN_CMD_CHANGE_BUFFER_SIZE, STATUS_OK };
        send(fd, response, sizeof(response), 0);
    } else {
        log(ERROR, "Failed to change buffer size");
        const uint8_t response[4] = { CONFIG_VERSION, RSV, ADMIN_CMD_CHANGE_BUFFER_SIZE, STATUS_FAIL };
        send(fd, response, sizeof(response), 0);
    }

    return CONFIG_DONE; //TODO: lo hacemos persistnece?
}

unsigned handleAdminAcceptsNoAuthWrite(struct selector_key *key) {
    socksArgs->serverAcceptsNoAuth = true;

    uint8_t response[4] = { CONFIG_VERSION, RSV, ADMIN_CMD_ACCEPTS_NO_AUTH, STATUS_OK };
    send(key->fd, response, sizeof(response), 0);

    return CONFIG_DONE;
}

unsigned handleAdminRejectsNoAuthWrite(struct selector_key *key) {
    socksArgs->serverAcceptsNoAuth = false;

    uint8_t response[4] = { CONFIG_VERSION, RSV, ADMIN_CMD_REJECTS_NO_AUTH, STATUS_OK };
    send(key->fd, response, sizeof(response), 0);

    return CONFIG_DONE;
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
    const uint8_t response[4] = { CONFIG_VERSION, RSV, ADMIN_CMD_ADD_USER, STATUS_OK };
        send(fd, response, sizeof(response), 0);
    } else {
        log(ERROR, "Failed to add user");
    const uint8_t response[4] = { CONFIG_VERSION, RSV, ADMIN_CMD_ADD_USER, STATUS_FAIL };
        send(fd, response, sizeof(response), 0);
    }

    return CONFIG_DONE; //TODO: lo hacemos persistnece?
}

unsigned handleAdminRemoveUserRead(struct selector_key * key) {
    const clientConfigData *data = key->data;
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
    if (ulen > 0) memcpy(username,buffer_read_ptr(data->clientBuffer, &available),  ulen);

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
    const clientConfigData *data = key->data;
    const int fd = key->fd;
    const int flag = buffer_read(data->clientBuffer);

    if (flag) {
        const uint8_t response[4] = { CONFIG_VERSION, RSV, ADMIN_CMD_REMOVE_USER, STATUS_OK };
        send(fd, response, sizeof(response), 0);
    } else {
        log(ERROR, "Failed to remove user");
        const uint8_t response[4] = { CONFIG_VERSION, RSV, ADMIN_CMD_REMOVE_USER, STATUS_FAIL };
        send(fd, response, sizeof(response), 0);
    }

    return CONFIG_DONE; //TODO: lo hacemos persistnece?
}


unsigned handleAdminMakeAdminRead(struct selector_key * key) {
    const clientConfigData *data = key->data;
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

    if (numBytesRcvd < 2) return ADMIN_MAKE_ADMIN_READ; // versión, rsv, código (1 byte)

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
        const uint8_t response[4] = { CONFIG_VERSION, RSV, ADMIN_CMD_MAKE_ADMIN, STATUS_OK };
        send(fd, response, sizeof(response), 0);
    } else {
        log(ERROR, "Failed to make admin user");
        const uint8_t response[4] = { CONFIG_VERSION, RSV, ADMIN_CMD_MAKE_ADMIN, STATUS_FAIL };
        send(fd, response, sizeof(response), 0);
    }

    return CONFIG_DONE; //TODO: lo hacemos persistnece?
}
