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
   READ_HEADER,
   READ_CREDENTIALS,
   AUTH_DONE,
   ADMIN_MENU,
   ADMIN_METRIC_SCOPE,
   ADMIN_METRIC_REQUEST,
   USER_METRICS,
   SEND_RESPONSE,
   CONFIG_DONE
} config_state;

// Información del cliente en la conexión de configuración
typedef struct {
    buffer *clientBuffer;
    struct state_machine *stm;
    config_state state;
    size_t bytes_read;
    uint8_t userlen;
    uint8_t passlen;
    enum Role { ROL_INVALID = -1, ROL_USER = 0, ROL_ADMIN = 1 } role;
    struct auth_config_info {
        char username[256];
        char password[256];
    } authInfo;
} clientConfigData;

#endif
