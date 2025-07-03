#include "tcpServerConfigUtil.h"
#include "../utils/logger.h"
#include "../utils/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#define BUFSIZE 1024
#define MAX_ADDR_BUFFER 128
static char addrBuffer[MAX_ADDR_BUFFER];


#define MAEP_VERSION 0x02
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
    if (version != MAEP_VERSION) {
        log(ERROR, "Unsupported MAEP version: %u", version);
        return CONFIG_DONE;
    }

    data->userlen = buffer_read(data->clientBuffer);
    data->passlen = buffer_read(data->clientBuffer);

    buffer_read_ptr(data->clientBuffer, &available);
    if (available < data->userlen + data->passlen) return READ_CREDENTIALS;

    const uint8_t *ptr = buffer_read_ptr(data->clientBuffer, NULL);
    memcpy(data->authInfo.username, ptr, data->userlen);
    data->authInfo.username[data->userlen] = '\0';
    buffer_read_adv(data->clientBuffer, data->userlen);

    ptr = buffer_read_ptr(data->clientBuffer, NULL);
    memcpy(data->authInfo.password, ptr, data->passlen);
    data->authInfo.password[data->passlen] = '\0';
    buffer_read_adv(data->clientBuffer, data->passlen);

    log(INFO, "Received username: %s", data->authInfo.username);
    log(INFO, "Received password: %s", data->authInfo.password);

    // Autenticación simplificada
    if (strcmp(data->authInfo.username, "admin") == 0 && strcmp(data->authInfo.password, "adminpass") == 0) {
        data->role = ROL_ADMIN;
    } else if (strcmp(data->authInfo.username, "user") == 0 && strcmp(data->authInfo.password, "userpass") == 0) {
        data->role = ROL_USER;
    } else {
        data->role = ROL_INVALID;
    }

    selector_set_interest_key(key, OP_WRITE);
    return AUTH_DONE;
}

unsigned handleAuthConfigWrite(struct selector_key *key) {
    int clntSocket = key->fd;
    clientConfigData *data = key->data;

    uint8_t response[3] = { MAEP_VERSION, STATUS_FAIL, ROLE_USER };
    if (data->role == ROL_ADMIN) {
        response[1] = STATUS_OK;
        response[2] = ROLE_ADMIN;
    } else if (data->role == ROL_USER) {
        response[1] = STATUS_OK;
        response[2] = ROLE_USER;
    }

    const ssize_t sent = send(clntSocket, response, sizeof(response), MSG_DONTWAIT);
    if (sent < 0) {
        log(ERROR, "send() failed on client socket %d", clntSocket);
        return CONFIG_DONE;
    }

    if (data->role == ROL_INVALID) {
        log(ERROR, "Authentication failed for client socket %d", clntSocket);
        return CONFIG_DONE;
    }

    log(INFO, "Authenticated client %s as %s", data->authInfo.username,
        data->role == ROL_ADMIN ? "ADMIN" : "USER");

    selector_set_interest_key(key, OP_READ);
    return (data->role == ROL_ADMIN) ? ADMIN_MENU : USER_METRICS;
}


static const struct state_definition states[] = {
    [READ_HEADER] = {
        .state = READ_HEADER,
        .on_read_ready = handleAuthConfigRead,
    },
    [READ_CREDENTIALS] = {
        .state = READ_CREDENTIALS,
        .on_read_ready = handleAuthConfigRead,
    },
    [AUTH_DONE] = {
        .state = AUTH_DONE,
        .on_write_ready = handleAuthConfigWrite,
    },
};

int initializeClientConfigData(clientConfigData *data) {
    struct state_machine *stm = malloc(sizeof(struct state_machine));
    if (stm == NULL) return -1;
    stm->initial = READ_HEADER;
    stm->states = states;
    stm->max_state = AUTH_DONE;
    stm_init(stm);

    buffer *buf = malloc(sizeof(buffer));
    if (buf == NULL) {
        free(stm);
        return -1;
    }
    buf->data = malloc(BUFSIZE);
    if (buf->data == NULL) {
        free(buf);
        free(stm);
        return -1;
    }
    buffer_init(buf, BUFSIZE, buf->data);
    data->clientBuffer = buf;
    data->stm = stm;
    data->state = READ_HEADER;
    data->bytes_read = 0;
    data->userlen = 0;
    data->passlen = 0;
    data->role = ROL_INVALID;
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
    if (!data || initializeClientConfigData(data) < 0) {
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

int acceptTCPConfigConnection(int servSock) {
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



