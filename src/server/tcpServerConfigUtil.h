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

#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64

typedef enum {
    READ_CREDENTIALS,         // Recibir: VERSION RSV ULEN USER PLEN PASS
    AUTH_DONE,                // Enviar resultado de autenticación

    // USER: métricas personales
    USER_METRICS,             // Enviar métricas del usuario autenticado

    // ADMIN
    ADMIN_INITIAL_REQUEST_READ,  // VERSION RSV CMD ULEN USERNAME (CMD = 0 stats, 1 config)
    ADMIN_INITIAL_REQUEST_WRITE,
    ADMIN_METRICS_SEND,          // Enviar métricas globales o de usuario

    ADMIN_COMMAND_READ,          // Esperar comandos de configuración
    ADMIN_MENU_READ,           // Nuevo estado: espera nuevo comando del admin
    ADMIN_MENU_WRITE,          // Enviar menú de comandos al admin


    ADMIN_BUFFER_SIZE_CHANGE,    // Cambiar tamaño de buffer
    ADMIN_BUFFER_SIZE_CHANGE_READ,
    ADMIN_ACCEPTS_NO_AUTH,       // Cambiar flag no-auth on
    ADMIN_REJECTS_NO_AUTH,       // Cambiar flag no-auth off
    ADMIN_ADD_USER,              // Agregar usuario
    ADMIN_ADD_USER_READ,
    ADMIN_REMOVE_USER,           // Quitar usuario
    ADMIN_REMOVE_USER_READ,
    ADMIN_MAKE_ADMIN,            // Convertir usuario en admin
    ADMIN_MAKE_ADMIN_READ,

    CONFIG_DONE,                 // Finaliza sesión/config
    ERROR_CONFIG_CLIENT          // Error fatal
} config_state;

typedef enum {
    GLOBAL_STATS ,
    CONFIG
}request_type;

typedef enum {
    ADMIN_CMD_CHANGE_BUFFER_SIZE   = 0x00,
    ADMIN_CMD_ACCEPTS_NO_AUTH      = 0x01,
    ADMIN_CMD_REJECTS_NO_AUTH      = 0x02,
    ADMIN_CMD_ADD_USER            = 0x03,
    ADMIN_CMD_REMOVE_USER         = 0x04,
    ADMIN_CMD_MAKE_ADMIN          = 0x05
} admin_command_code;


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
    uint8_t admin_cmd; // 0 = stats, 1 = config
    char target_username[MAX_USERNAME_LEN];
    uint8_t target_ulen;
    char target_password[MAX_PASSWORD_LEN];
    uint8_t target_plen;
} clientConfigData;

#endif
