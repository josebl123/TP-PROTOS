#ifndef TCP_SERVER_CONFIG_UTIL_H
#define TCP_SERVER_CONFIG_UTIL_H

#include "../selector.h"
#include <sys/socket.h>
#include "../stm.h"
#include "../buffer.h"
#include <netdb.h>

void handleConfigRead(struct selector_key *key);
void handleConfigClose(struct selector_key *key);
void config_close(struct selector_key *key);
void config_read(struct selector_key *key);
void config_write(struct selector_key *key);
int acceptTCPConfigConnection(int servSock);

// Estados de la máquina de estados MAEP-S5
typedef enum {
    READ_CREDENTIALS,
    AUTH_DONE,
    USER_METRICS,
    ADMIN_MENU_SEND,
    ADMIN_MENU_READ,
    ADMIN_SCOPE_READ,
    ADMIN_METRICS_SEND,
    CONFIG_DONE,
    ERROR_CONFIG_CLIENT
} config_state;

// Información del cliente en la conexión de configuración
typedef struct {
    buffer *clientBuffer;
    struct state_machine *stm;
    config_state state;
    size_t bytes_read;
    uint8_t userlen;
    uint8_t passlen;
    enum Role { ROLE_INVALID = -1, ROLE_USER = 0, ROLE_ADMIN = 1 } role;
    struct auth_config_info {
        char username[256];
        char password[256];
    } authInfo;
    char *metrics_buf;
    size_t metrics_buf_len;
    size_t metrics_buf_offset;
} clientConfigData;

#endif
