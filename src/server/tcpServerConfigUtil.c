#include "tcpServerConfigUtil.h"
#include "../utils/logger.h"
#include "../utils/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "rbt.h"
#include "../metrics/metrics.h"
#include "utils/user_metrics_table.h"
#include "server.h"
#include <errno.h>

#define MAX_ADDR_BUFFER 128
#define METRICS_BUF_CHUNK 4096


#define CONFIG_VERSION 0x01
#define STATUS_OK 0x00
#define STATUS_FAIL 0x01
#define ROLE_USER 0x00
#define ROLE_ADMIN 0x01


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
    buffer_read_ptr(data->clientBuffer, &available);


    if (available < 3) return READ_CREDENTIALS;

    uint8_t version = buffer_read(data->clientBuffer);
    if (version != CONFIG_VERSION) {
        log(ERROR, "Unsupported MAEP version: %u", version);
        return CONFIG_DONE;
    }

    data->userlen = buffer_read(data->clientBuffer);
    data->passlen = buffer_read(data->clientBuffer);

    log(INFO, "userlen: %u, passlen: %u", data->userlen, data->passlen);

    buffer_read_ptr(data->clientBuffer, &available);
    if (available < data->userlen + data->passlen) return READ_CREDENTIALS;

    // if (data->userlen >= sizeof(data->authInfo.username) || TODO:imposible que pase esto por el tamaño del buffer
    //     data->passlen >= sizeof(data->authInfo.password)) {
    //     log(ERROR, "Username or password too long, userlen=%u passlen=%u", data->userlen, data->passlen);
    //     return CONFIG_DONE;
    // }

    const uint8_t *ptr = buffer_read_ptr(data->clientBuffer, &available);
    if (ptr == NULL || available < data->userlen) {
        log(ERROR, "Failed to read username from buffer");
        return CONFIG_DONE;
    }
    memcpy(data->authInfo.username, ptr, data->userlen);
    data->authInfo.username[data->userlen] = '\0';
    buffer_read_adv(data->clientBuffer, data->userlen);

    ptr = buffer_read_ptr(data->clientBuffer, &available);
    if (ptr == NULL || available < data->passlen) {
        log(ERROR, "Failed to read password from buffer");
        return CONFIG_DONE;
    }
    memcpy(data->authInfo.password, ptr, data->passlen);
    data->authInfo.password[data->passlen] = '\0';
    buffer_read_adv(data->clientBuffer, data->passlen);

    log(INFO, "Received username: %s", data->authInfo.username);
    log(INFO, "Received password: %s", data->authInfo.password);

    if (strcmp(data->authInfo.username, "admi") == 0 && strcmp(data->authInfo.password, "userpass") == 0) {
        data->role = ROLE_ADMIN;
    } else if (strcmp(data->authInfo.username, "user") == 0 && strcmp(data->authInfo.password, "userpass") == 0) {
        data->role = ROLE_USER;
    } else {
        data->role = ROLE_INVALID;
    }

    selector_set_interest_key(key, OP_WRITE);
    return AUTH_DONE;
}

unsigned handleAuthConfigWrite(struct selector_key *key) {
    int clntSocket = key->fd;
    clientConfigData *data = key->data;

    uint8_t response[3] = { CONFIG_VERSION, STATUS_FAIL, ROLE_USER };
    if (data->role == ROLE_ADMIN) {
        response[1] = STATUS_OK;
        response[2] = ROLE_ADMIN;
    } else if (data->role == ROLE_USER) {
        response[1] = STATUS_OK;
        response[2] = ROLE_USER;
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

    selector_set_interest_key(key, OP_WRITE);
    return (data->role == ROLE_ADMIN) ? ADMIN_MENU_SEND : USER_METRICS;
}

unsigned handleUserMetricsWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    int clntSocket = key->fd;

    if (data->metrics_buf == NULL) {
        size_t bufsize = METRICS_BUF_CHUNK;
        char *buffer = malloc(bufsize);
        if (!buffer) {
            return CONFIG_DONE;
        }

        FILE *memfile = fmemopen(buffer, bufsize, "w");
        if (!memfile) {
            free(buffer);
            return CONFIG_DONE;
        }

        user_metrics *um = get_or_create_user_metrics(data->authInfo.username);
        if (!um) {
            log(ERROR, "User metrics not found for %s", data->authInfo.username);
            fclose(memfile);
            free(buffer);
            return CONFIG_DONE;
        }

        log(INFO, "Found metrics for user %s, tree root: %p", data->authInfo.username, (void *) um->connections_tree.root);


        print_user_metrics_tabbed(um, data->authInfo.username, memfile);
        fflush(memfile);

        size_t written = ftell(memfile);
        fclose(memfile);

        data->metrics_buf = buffer;
        data->metrics_buf_len = written;
        data->metrics_buf_offset = 0;
    }

    const size_t to_send = data->metrics_buf_len - data->metrics_buf_offset;
    const ssize_t sent = send(clntSocket, data->metrics_buf + data->metrics_buf_offset, to_send, MSG_DONTWAIT);
    if (sent < 0) {
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
    close(key->fd);
}
unsigned handleAdminMenuInitialWrite(struct selector_key *key) {
    int clntSocket = key->fd;

    const char *menu =
        "=== Admin Menu ===\n"
        "1) Ver métricas globales\n"
        "2) Ver metricas de un usuario\n"
        "3) Entrar a configuración del servidor\n"
        "4) Salir (elegir 4 y apretar dos veces enter)\n" //TODO: FIX THIS
        "Seleccione una opción: ";

    const ssize_t sent = send(clntSocket, menu, strlen(menu), MSG_DONTWAIT);
    if (sent < 0) {
        log(ERROR, "send() failed in admin menu write");
        return CONFIG_DONE;
    }

    selector_set_interest_key(key, OP_READ);
    return ADMIN_MENU_READ;
}

unsigned handleAdminMenuRead(struct selector_key *key) {
    log(INFO, "Entered ADMIN_MENU_READ");
    clientConfigData *data = key->data;
    int clntSocket = key->fd;

    size_t writeLimit;
    uint8_t *readPtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, readPtr, writeLimit, 0);
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed: %s", strerror(errno));
        return CONFIG_DONE;
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client closed connection");
        return CONFIG_DONE;
    }

    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    size_t avail;
    uint8_t *read_ptr = buffer_read_ptr(data->clientBuffer, &avail);
    if (avail == 0) return ADMIN_MENU_READ;

    // Busco un carácter válido (ignoro '\n', '\r' y espacios)
    char opt = '\0';
    while (avail > 0) {
        char c = (char)*read_ptr;
        buffer_read_adv(data->clientBuffer, 1);
        avail--;
        if (c != '\n' && c != '\r' && c != ' ') {
            opt = c;
            break;
        }
        read_ptr = buffer_read_ptr(data->clientBuffer, &avail);
    }

    if (opt == '\0') {
        selector_set_interest_key(key, OP_READ);
        return ADMIN_MENU_READ; // Esperá más input
    }

    log(INFO, "Admin option received: %c", opt);

    switch (opt) {
        case '1': //TODO: MAGIC NUMBERS
            selector_set_interest_key(key, OP_WRITE);
            return ADMIN_METRICS_SEND;
        case '2':
            selector_set_interest_key(key, OP_WRITE);
            return ADMIN_SCOPE_MENU_SEND;
        case '3':
            return ADMIN_CONFIG_READ;
        case '4':
            buffer_reset(data->clientBuffer);  // <<< Limpia el buffer
            return CONFIG_DONE;
        default: {
            const char *msg = "Opción inválida.\nSeleccione una opción: ";
            send(clntSocket, msg, strlen(msg), MSG_DONTWAIT);
            buffer_reset(data->clientBuffer);  // <<< Limpia el buffer
            selector_set_interest_key(key, OP_READ);
            return ADMIN_MENU_READ;
        }
    }
}


unsigned handleAdminScopeMenuWrite(struct selector_key *key) {
    int clntSocket = key->fd;

    const char *prompt = "Ingrese el nombre de usuario: ";

    ssize_t sent = send(clntSocket, prompt, strlen(prompt), MSG_DONTWAIT);
    if (sent < 0) {
        log(ERROR, "send() failed in handleAdminScopeMenuWrite");
        return CONFIG_DONE;
    }

    selector_set_interest_key(key, OP_READ);
    return ADMIN_SCOPE_READ;
}


unsigned handleAdminScopeRead(struct selector_key *key) {
    log(INFO, "Entered handleAdminScopeRead");
    clientConfigData *data = key->data;
    int clntSocket = key->fd;

    size_t writeLimit;
    uint8_t *readPtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    ssize_t numBytesRcvd = recv(clntSocket, readPtr, writeLimit, 0);
    if (numBytesRcvd <= 0) {
        log(ERROR, "recv() failed or connection closed");
        return CONFIG_DONE;
    }
    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    size_t avail;
    const uint8_t *read_ptr = buffer_read_ptr(data->clientBuffer, &avail);

    // Busco \n o \r
    size_t i;
    for (i = 0; i < avail; i++) {
        if (read_ptr[i] == '\n' || read_ptr[i] == '\r') {
            break;
        }
    }

    // Si no encontré el final de línea aún, espero más input
    if (i == avail) {
        selector_set_interest_key(key, OP_READ);
        return ADMIN_SCOPE_READ;
    }

    // i ahora es la posición del \n
    const size_t copyLen = (i < sizeof(data->target_username) - 1) ? i : sizeof(data->target_username) - 1;

    memset(data->target_username, 0, sizeof(data->target_username));
    memcpy(data->target_username, read_ptr, copyLen);
    data->target_username[copyLen] = '\0';

    buffer_read_adv(data->clientBuffer, i + 1);  // Saltea \n o \r también

    log(INFO, "Admin selected user: %s", data->target_username);

    selector_set_interest_key(key, OP_WRITE);
    return ADMIN_SCOPE_WRITE;
}



unsigned handleAdminScopeWrite(struct selector_key * key) {
    clientConfigData *data = key->data;
    int clntSocket = key->fd;

    if (data->metrics_buf == NULL) {
        size_t bufsize = METRICS_BUF_CHUNK;
        char *buffer = malloc(bufsize);
        if (!buffer) {
            return CONFIG_DONE;
        }

        FILE *memfile = fmemopen(buffer, bufsize, "w");
        if (!memfile) {
            free(buffer);
            return CONFIG_DONE;
        }

        user_metrics *um = get_or_create_user_metrics("admi"); //TODO: THIS IS HARDCODDED TO TEST IT
        if (!um) {
            const char *msg = "Usuario no encontrado.\n";
            send(clntSocket, msg, strlen(msg), MSG_DONTWAIT);
            fclose(memfile);
            free(buffer);
            return ADMIN_MENU_SEND;
        }

        print_user_metrics_tabbed(um, "admi", memfile); //TODO: THIS IS HARDCODDED TO TEST IT
        fflush(memfile);
        size_t written = ftell(memfile);
        fclose(memfile);

        data->metrics_buf = buffer;
        data->metrics_buf_len = written;
        data->metrics_buf_offset = 0;
    }

    size_t to_send = data->metrics_buf_len - data->metrics_buf_offset;
    ssize_t sent = send(clntSocket, data->metrics_buf + data->metrics_buf_offset, to_send, MSG_DONTWAIT);
    if (sent < 0) return CONFIG_DONE;

    data->metrics_buf_offset += sent;

    if (data->metrics_buf_offset >= data->metrics_buf_len) {
        free(data->metrics_buf);
        data->metrics_buf = NULL;
        data->metrics_buf_len = 0;
        data->metrics_buf_offset = 0;

        buffer_reset(data->clientBuffer);  // <<< AGREGÁ ESTO
        return ADMIN_MENU_SEND;
    }


    return ADMIN_SCOPE_WRITE;
}

unsigned handleAdminMetricsWrite(struct selector_key *key) {
    clientConfigData *data = key->data;
    int clntSocket = key->fd;

    if (data->metrics_buf == NULL) {
        size_t bufsize = METRICS_BUF_CHUNK;
        char *buffer = malloc(bufsize);
        if (!buffer) return CONFIG_DONE;

        FILE *memfile = fmemopen(buffer, bufsize, "w");
        if (!memfile) {
            free(buffer);
            return CONFIG_DONE;
        }

        // Imprimir las métricas globales en el buffer
        print_global_metrics(memfile);
        fflush(memfile);

        size_t written = ftell(memfile);
        fclose(memfile);

        data->metrics_buf = buffer;
        data->metrics_buf_len = written;
        data->metrics_buf_offset = 0;
    }

    const size_t to_send = data->metrics_buf_len - data->metrics_buf_offset;
    const ssize_t sent = send(clntSocket, data->metrics_buf + data->metrics_buf_offset, to_send, MSG_DONTWAIT);
    if (sent < 0) {
        return CONFIG_DONE;
    }

    data->metrics_buf_offset += sent;

    if (data->metrics_buf_offset >= data->metrics_buf_len) {
        free(data->metrics_buf);
        data->metrics_buf = NULL;
        data->metrics_buf_len = 0;
        data->metrics_buf_offset = 0;

        buffer_reset(data->clientBuffer);  // <<< AGREGÁ ESTO TAMBIÉN
        return ADMIN_MENU_SEND;  // Volver al menú
    }

    return ADMIN_METRICS_SEND;
}


unsigned handleAdminConfigRead(struct selector_key * key) {
    return 1;
}unsigned handleAdminConfigWrite(struct selector_key * key) {
    return 1;
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
    [ADMIN_MENU_SEND] = {
        .state = ADMIN_MENU_SEND,
        .on_write_ready = handleAdminMenuInitialWrite,
    },
    [ADMIN_MENU_READ] = {
        .state = ADMIN_MENU_READ,
        .on_read_ready = handleAdminMenuRead,
    },
    [ADMIN_SCOPE_READ] = {
        .state = ADMIN_SCOPE_READ,
        .on_read_ready = handleAdminScopeRead,
    },
    [ADMIN_SCOPE_MENU_SEND] = {
        .state = ADMIN_SCOPE_MENU_SEND,
        .on_write_ready = handleAdminScopeMenuWrite,
    },
    [ADMIN_SCOPE_WRITE] = {
        .state = ADMIN_SCOPE_WRITE,
        .on_write_ready = handleAdminScopeWrite,
    },
    [ADMIN_METRICS_SEND] = {
        .state = ADMIN_METRICS_SEND,
        .on_write_ready = handleAdminMetricsWrite,
    },
    [ADMIN_CONFIG_READ] = {
        .state = ADMIN_CONFIG_READ,
        .on_read_ready = handleAdminConfigRead,
    },
    [ADMIN_CONFIG_WRITE] = {
        .state = ADMIN_CONFIG_WRITE,
        .on_write_ready = handleAdminConfigWrite,
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



