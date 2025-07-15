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
#include <errno.h>
#include "server.h"
#include "serverConfigTypes.h"
#include "tcpServerConfigUtil.h"
#define METRICS_WRITE_HEADER_SIZE 3 // Size of the metrics header (version, rsv, status, role)
#define METRICS_WRITE_PAYLOAD_LENGTH 4
#define BUFFER_CHANGE_REQUEST_SIZE 5 // Size of the buffer change request (version, rsv, new size)
#define ADD_USER_MIN_LENGTH 4

int make_admin(char *username, uint8_t ulen) {
    if (socks_args == NULL) {
        log(ERROR, "socks_args o users array es NULL");
        return false;
    }

    for (size_t i = 0; i < MAX_USERS; i++) {
        if (socks_args->users[i].name != NULL &&
            strncmp(socks_args->users[i].name, username, ulen) == 0) {
            if (socks_args->users[i].is_admin) {
                log(ERROR, "El usuario %s ya es admin", username);
                return false;
            }
            socks_args->users[i].is_admin = true;
            log(INFO, "Usuario %s promovido a admin", username);
            return true;
            }
    }
    log(ERROR, "Usuario %s no encontrado", username);
    return false;
}

int remove_user(char * username, uint8_t ulen) {
        if (socks_args == NULL ) {
        log(ERROR, "socks_args or users array is NULL");
        return false;
        }

    // Busca el usuario a borrar
    for (size_t i = 0; i < MAX_USERS; i++) {
        if (socks_args->users[i].name != NULL && strncmp(socks_args->users[i].name, username, ulen) == 0) {
            // Busca el último usuario válido
            size_t last = MAX_USERS;
            for (size_t j = 0; j < MAX_USERS; j++) {
                if (socks_args->users[j].name == NULL) {
                    last = j;
                    break;
                }
            }
            if (last == 0) return false; // No hay usuarios

            const size_t last_idx = last - 1;
            remove_user_metrics(socks_args->users[i].name);
            if (i != last_idx) {
                // Libera el usuario a borrar
                // Copia el último usuario en la posición borrada
                socks_args->users[i].name = socks_args->users[last_idx].name;
                socks_args->users[i].pass = socks_args->users[last_idx].pass;
                socks_args->users[i].is_admin = socks_args->users[last_idx].is_admin;
            }
            if (socks_args->users[i].is_added) {
                free(socks_args->users[i].name);
                free(socks_args->users[i].pass);
            }
            // Marca el último como vacío
            socks_args->users[last_idx].name = NULL;
            socks_args->users[last_idx].pass = NULL;
            socks_args->users[last_idx].is_admin = false;
            socks_args->users[last_idx].is_added = false; // Marca como no agregado
            return true;
        }
    }
    log(ERROR, "User %s not found", username);
    return false;

}

unsigned add_user( char * username, const uint8_t ulen,  char *password, const uint8_t passlen, const bool is_admin) {
    if (socks_args == NULL ) {
        log(ERROR, "socks_args or users array is NULL");
        return false;
    }

    for (size_t i = 0; i < MAX_USERS; i++) {
        if ( socks_args->users[i].name != NULL &&
            strncmp(socks_args->users[i].name, username, ulen) == 0) {
            log(ERROR, "User %s already exists", username);
            return false; // User already exists
            }
        if (socks_args->users[i].name == NULL) {
            // Found an empty slot
            socks_args->users[i].name = malloc(ulen + 1);
            socks_args->users[i].pass = malloc(passlen + 1);
            if (socks_args->users[i].name == NULL || socks_args->users[i].pass == NULL) {
                log(ERROR, "Memory allocation failed for new user");
                return false;
            }
            strncpy(socks_args->users[i].name, username, ulen);
            strncpy(socks_args->users[i].pass, password, passlen);
            socks_args->users[i].name[ulen] = '\0'; // Initialize to empty string
            socks_args->users[i].pass[passlen] = '\0'; // Initialize to empty string
            socks_args->users[i].is_admin = is_admin;
            socks_args->users[i].is_added = true; // Mark as added
            return true;
        }
    }
    log(ERROR, "User limit reached, cannot add more users");
    return false;
}
unsigned attempt_admin_buffer_size_change_write(struct selector_key *key, bool flag) {
    const client_config_data *data = key->data;
    buffer_reset(data->client_buffer);
    buffer_write(data->client_buffer, CONFIG_VERSION);
    buffer_write(data->client_buffer, RSV);
    buffer_write(data->client_buffer, ADMIN_CMD_CHANGE_BUFFER_SIZE);
    buffer_write(data->client_buffer, flag ? STATUS_OK : STATUS_SERVER_GENERAL_FAILURE);
    return handle_admin_buffer_size_change_write(key);
}

unsigned handle_admin_buffer_size_change_read(struct selector_key * key) {
    const client_config_data *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->client_buffer, &available);

    const ssize_t num_bytes_rcvd = recv(fd, ptr, available, 0);
    if (num_bytes_rcvd <= 0) {
        if (num_bytes_rcvd == 0) {
            log(INFO, "Client socket %d closed connection", fd);
            return CONFIG_DONE;
        }
        log(ERROR, "recv() failed on client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }

    buffer_write_adv(data->client_buffer, num_bytes_rcvd);
    size_t read_available;
    buffer_read_ptr(data->client_buffer, &read_available);

    if (read_available < BUFFER_CHANGE_REQUEST_SIZE) return ADMIN_BUFFER_SIZE_CHANGE_READ; // versión, rsv, código (1 byte)
    // Saltar los primeros 4 bytes
    buffer_read_adv(data->client_buffer, BUFFER_CHANGE_REQUEST_SIZE -1);

    // Leer el nuevo buffer_size (por ejemplo, como uint32_t en network order)
    const uint32_t new_buf_size = ntohl(*(uint32_t *)buffer_read_ptr(data->client_buffer, &available));
    log(INFO, "Received new buffer size: %u", new_buf_size);
    int flag = 1;

    if (new_buf_size < MIN_BUFFER_SIZE || new_buf_size > MAX_BUFFER_SIZE) {
        flag = 0;
    } else {
        buffer_size = new_buf_size;
    }

    return attempt_admin_buffer_size_change_write(key, flag);
}
unsigned generic_write(struct selector_key * key, unsigned next_state, unsigned current_state) {
    const client_config_data *data = key->data;
    const int fd = key->fd;
    size_t available;
    const uint8_t *ptr = buffer_read_ptr(data->client_buffer, &available);
    const ssize_t num_bytes_sent = send(fd, ptr, available, 0);
    if (num_bytes_sent < 0) {
        if (errno == ECONNRESET) {
            log(INFO, "Client socket %d closed connection", fd);
            return CONFIG_DONE; // El cliente cerró la conexión
        }
        if ( errno == EAGAIN || errno == EWOULDBLOCK) {
            log(INFO, "Socket %d would block, try again later", fd);
            return current_state; // El socket está bloqueado, intenta de nuevo
        }
        return ERROR_CONFIG_CLIENT;
    }
    if (num_bytes_sent == 0) {
        log(INFO, "Client socket %d closed connection", fd);
        return CONFIG_DONE; // El cliente cerró la conexión
    }
    if (num_bytes_sent < (ssize_t)available) {
        log(ERROR, "Partial write on client socket %d", fd);
        return current_state; // No se envió todo, intenta de nuevo
    }
    buffer_read_adv(data->client_buffer, num_bytes_sent); // Avanzar el puntero de lectura del buffer

    return next_state;
}
unsigned handle_admin_buffer_size_change_write(struct selector_key *key) {
    return generic_write(key, CONFIG_DONE, ADMIN_BUFFER_SIZE_CHANGE);
}
unsigned attempt_admin_accepts_auth_write(struct selector_key *key, bool accepts) {
    const client_config_data *data = key->data;
    socks_args->server_accepts_no_auth = accepts;
    buffer_reset(data->client_buffer);
    buffer_write(data->client_buffer, CONFIG_VERSION);
    buffer_write(data->client_buffer, RSV);
    buffer_write(data->client_buffer, accepts? ADMIN_CMD_ACCEPTS_NO_AUTH : ADMIN_CMD_REJECTS_NO_AUTH);
    buffer_write(data->client_buffer, STATUS_OK);
    return accepts ? handle_admin_accepts_no_auth_write(key): handle_admin_rejects_no_auth_write(key);
}

unsigned handle_admin_accepts_no_auth_write(struct selector_key *key) {
    return generic_write(key, CONFIG_DONE, ADMIN_ACCEPTS_NO_AUTH);
}

unsigned handle_admin_rejects_no_auth_write(struct selector_key *key) {
    return generic_write(key, CONFIG_DONE, ADMIN_REJECTS_NO_AUTH);
}
unsigned attempt_admin_add_user_write(struct selector_key *key, bool flag) {
    const client_config_data *data = key->data;
    buffer_reset(data->client_buffer);
    buffer_write(data->client_buffer, CONFIG_VERSION);
    buffer_write(data->client_buffer, RSV);
    buffer_write(data->client_buffer, ADMIN_CMD_ADD_USER);
    buffer_write(data->client_buffer, flag ? STATUS_OK : STATUS_SERVER_GENERAL_FAILURE);
    return handle_admin_add_user_write(key);
}


unsigned handle_admin_add_user_read(struct selector_key * key) {
    const client_config_data *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->client_buffer, &available);

    const ssize_t num_bytes_rcvd = recv(fd, ptr, available, 0);
    if (num_bytes_rcvd <= 0) {
        if (num_bytes_rcvd == 0) {
            log(INFO, "Client socket %d closed connection", fd);
            return CONFIG_DONE;
        }
        log(ERROR, "recv() failed on client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }

    buffer_write_adv(data->client_buffer, num_bytes_rcvd);

    size_t read_available;
    const uint8_t * read_ptr= buffer_read_ptr(data->client_buffer, &read_available);

    if (read_available < ADD_USER_MIN_LENGTH) return ADMIN_ADD_USER_READ; // versión, rsv, código (1 byte)

    const uint8_t ulen = read_ptr[0] ;
    if (ulen > MAX_USERNAME_LEN || ulen < 1) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", fd);
            return ERROR_CONFIG_CLIENT;
        }
        return attempt_send_bad_request_error(key);    }
    if (read_available < (size_t)ulen + 1) { // Se necesitan al menos 3 bytes para versión, rsv y código
        return ADMIN_ADD_USER_READ; // No hay suficientes bytes para el nombre de usuario
    }

    const uint8_t passlen = read_ptr[ulen + 1];
    if (passlen > MAX_PASSWORD_LEN || passlen < 1) {
        log(ERROR, "Password length exceeds maximum: %u", passlen);
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", fd);
            return ERROR_CONFIG_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }
    if (read_available < (size_t)ulen + 1 + (size_t)passlen + 1) {
        return ADMIN_ADD_USER_READ;
    }
    char username[MAX_USERNAME_LEN + 1] = {0};
    char password[MAX_PASSWORD_LEN + 1] = {0};
    memcpy(username,    read_ptr + 1,  ulen);
    buffer_read_adv(data->client_buffer, ulen + 1); // Avanzar el buffer para saltar el nombre de usuario
    read_ptr = buffer_read_ptr(data->client_buffer, &available);

    memcpy(password, read_ptr + 1 ,passlen);
    buffer_read_adv(data->client_buffer,  passlen +1);
    bool flag = 1;

    if (!add_user(username, ulen, password, passlen,false)) {
        flag = 0;
    }


    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }
    return attempt_admin_add_user_write(key, flag);
}

unsigned handle_admin_add_user_write(struct selector_key *key) {
    return generic_write(key, CONFIG_DONE, ADMIN_ADD_USER);
}

unsigned attempt_admin_remove_user_write(struct selector_key *key, bool flag) {
    const client_config_data *data = key->data;
    buffer_reset(data->client_buffer);
    buffer_write(data->client_buffer, CONFIG_VERSION);
    buffer_write(data->client_buffer, RSV);
    buffer_write(data->client_buffer, ADMIN_CMD_REMOVE_USER);
    buffer_write(data->client_buffer, flag ? STATUS_OK : STATUS_SERVER_GENERAL_FAILURE);
    return handle_admin_remove_user_write(key);
}

unsigned handle_admin_remove_user_read(struct selector_key * key) {
    const client_config_data *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->client_buffer, &available);

    const ssize_t num_bytes_rcvd = recv(fd, ptr, available, 0);
    if (num_bytes_rcvd <= 0) {
        if (num_bytes_rcvd == 0) {
            log(INFO, "Client socket %d closed connection", fd);
            return CONFIG_DONE;
        }
        log(ERROR, "recv() failed on client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }

    buffer_write_adv(data->client_buffer, num_bytes_rcvd);
    char username[MAX_USERNAME_LEN + 1] = {0};
    size_t read_available;
    const uint8_t * read_ptr = buffer_read_ptr(data->client_buffer, &read_available);

    if (read_available < 1) return ADMIN_REMOVE_USER_READ; // versión, rsv, código (1 byte)

    const uint8_t ulen = read_ptr[0];
    if (ulen > MAX_USERNAME_LEN || ulen < 1) {
        log(ERROR, "Username length exceeds maximum: %u", ulen);
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", fd);
            return ERROR_CONFIG_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }
    if (read_available < (size_t)ulen + 1) { // Se necesitan al menos 3 bytes para versión, rsv y código
        return ADMIN_REMOVE_USER_READ; // No hay suficientes bytes para el nombre de usuario
    }

    memcpy(username,read_ptr + 1,  ulen);

    buffer_read_adv(data->client_buffer, ulen + 1);

    int flag = 1;

    log(INFO, "received username: %s", username);
    log(INFO, "user length: %d", ulen);
    if (!remove_user(username, ulen)) {
        flag = 0;
    }

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }
    return attempt_admin_remove_user_write(key, flag);
}

unsigned handle_admin_remove_user_write(struct selector_key *key) {
    return generic_write(key, CONFIG_DONE, ADMIN_REMOVE_USER);
}
unsigned attempt_admin_make_admin_write(struct selector_key *key, bool flag) {
    const client_config_data *data = key->data;
    buffer_reset(data->client_buffer);
    buffer_write(data->client_buffer, CONFIG_VERSION);
    buffer_write(data->client_buffer, RSV);
    buffer_write(data->client_buffer, ADMIN_CMD_MAKE_ADMIN);
    buffer_write(data->client_buffer, flag ? STATUS_OK : STATUS_SERVER_GENERAL_FAILURE);
    return handle_admin_make_admin_write(key);
}

unsigned handle_admin_make_admin_read(struct selector_key * key) {
    const client_config_data *data = key->data;
    const int fd = key->fd;
    size_t available;
    uint8_t *ptr = buffer_write_ptr(data->client_buffer, &available);

    const ssize_t num_bytes_rcvd = recv(fd, ptr, available, 0);
    if (num_bytes_rcvd <= 0) {
        if (num_bytes_rcvd == 0) {
            log(INFO, "Client socket %d closed connection", fd);
            return CONFIG_DONE;
        }
        log(ERROR, "recv() failed on client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }

    buffer_write_adv(data->client_buffer, num_bytes_rcvd);
    size_t read_available;
    const uint8_t * read_ptr = buffer_read_ptr(data->client_buffer, &read_available);

    if (read_available < 1) return ADMIN_MAKE_ADMIN_READ; // versión, rsv, código (1 byte)

    const uint8_t ulen = read_ptr[0];
    if (ulen > MAX_USERNAME_LEN || ulen < 1) {
        log(ERROR, "Username length exceeds maximum: %u", ulen);
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", fd);
            return ERROR_CONFIG_CLIENT;
        }
        return attempt_send_bad_request_error(key);
    }
    char username[MAX_USERNAME_LEN + 1] = {0};
    memcpy(username,    read_ptr + 1,  ulen);

    buffer_read_adv(data->client_buffer, ulen + 1);

    int flag = 1;

    log(INFO, "received username: %s", username);
    if (!make_admin(username, ulen)) {
        flag = 0;
    }

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to set interest for client socket %d", fd);
        return ERROR_CONFIG_CLIENT;
    }
    return attempt_admin_make_admin_write(key, flag);
}

unsigned handle_admin_make_admin_write(struct selector_key *key) {
   return generic_write(key, CONFIG_DONE, ADMIN_MAKE_ADMIN);
}


bool prepare_user_metrics_buffer_from_auth(client_config_data *data) {
    char *buffer = NULL;
    size_t size = 0;

    FILE *memfile = open_memstream(&buffer, &size);
    if (!memfile) {
        return false;
    }

    user_metrics *um = get_or_create_user_metrics(data->auth_info.username);
    if (!um) {
        log(ERROR, "User metrics not found for %s", data->auth_info.username);
        fclose(memfile);
        free(buffer);
        return false;
    }

    print_user_metrics_tabbed(um, data->auth_info.username, memfile);
    fflush(memfile);
    fclose(memfile);  // Esto finaliza el stream y setea `size`


    const size_t total_len = METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH + size;
    char *full_buf = malloc(total_len);
    if (!full_buf) {
        free(buffer);
        return false;
    }

    full_buf[0] = CONFIG_VERSION;
    full_buf[1] = RSV;
    full_buf[2] = STATUS_OK;

    const uint32_t body_len = htonl(size);
    memcpy(full_buf + METRICS_WRITE_HEADER_SIZE, &body_len, METRICS_WRITE_PAYLOAD_LENGTH);
    memcpy(full_buf + METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH, buffer, size);

    free(buffer);

    data->metrics_buf = full_buf;
    data->metrics_buf_len = total_len;
    data->metrics_buf_offset = 0;
    return true;
}

unsigned send_metrics_fail_response(struct selector_key * key) {
    const client_config_data *data = key->data;
    const int clnt_socket = key->fd;

    size_t available;
    uint8_t *ptr = buffer_read_ptr(data->client_buffer, &available);

    ssize_t bytes_sent = send(clnt_socket, ptr, available, 0);
    if (bytes_sent < 0) {
        if (errno == ECONNRESET) {
            log(INFO, "Client socket %d closed connection", clnt_socket);
            return CONFIG_DONE; // El cliente cerró la conexión
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return SEND_FAILURE_RESPONSE; // El socket está bloqueado, intenta de nuevo
        }
        log(ERROR, "Failed to send metrics failure response to client socket %d: %s", clnt_socket, strerror(errno));
        return ERROR_CONFIG_CLIENT; // Error al enviar la respuesta de fallo
    } else if (bytes_sent < METRICS_FAILURE_RESPONSE_SIZE) {
        buffer_read_adv(data->client_buffer, bytes_sent);
        return SEND_FAILURE_RESPONSE; // No se envió , sigamos despues
    } else if (bytes_sent == 0) {
        log(INFO, "Client socket %d closed connection after sending metrics failure response", clnt_socket);
        return CONFIG_DONE; // El cliente cerró la conexión
    } else {
        log(INFO, "Metrics failure response sent to client socket %d", clnt_socket);
        return CONFIG_DONE;
    }
}

unsigned send_metrics_buffer(client_config_data *data, int clnt_socket, const unsigned next_state) {
    const size_t to_send = data->metrics_buf_len - data->metrics_buf_offset;
    const ssize_t sent = send(clnt_socket, data->metrics_buf + data->metrics_buf_offset, to_send, 0);
    if (sent < 0) {
        if (errno == ECONNRESET) {
            log(INFO, "Client socket %d closed connection", clnt_socket);
            return CONFIG_DONE; // El cliente cerró la conexión
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            log(INFO, "Socket %d would block, try again later", clnt_socket);
            return next_state; // El socket está bloqueado, intenta de nuevo
        }
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
        buffer_reset(data->client_buffer);
        return CONFIG_DONE;
    }
    return next_state;
}

void prepare_global_metrics_buffer(client_config_data *data) {
    char *buffer = NULL;
    size_t size = 0;

    FILE *memfile = open_memstream(&buffer, &size);
    if (!memfile) return;

    print_global_metrics(memfile);

    bool any_connection = false;
    fprintf(memfile, "\n==== ALL USER CONNECTIONS ====\n");
    for (size_t i = 0; i < MAX_USERS; i++) {
        if (socks_args->users[i].name != NULL) {
            user_metrics *um = get_or_create_user_metrics(socks_args->users[i].name);
            if (um && um->connections_tree.root != NULL) {
                print_all_users_metrics_tabbed(um, socks_args->users[i].name, memfile);
                any_connection = true;
            }
        }
    }
    user_metrics *um = get_or_create_user_metrics(ANONYMOUS_USER);
    if (um && um->connections_tree.root != NULL) {
        print_all_users_metrics_tabbed(um, ANONYMOUS_USER, memfile);
        any_connection = true;
    }
    if (!any_connection) {
        fprintf(memfile, "\nNO USER CONNECTIONS YET\n\n");
    }
    fprintf(memfile, "\n==== END OF ALL USER CONNECTIONS ====\n\n");

    fflush(memfile);
    fclose(memfile);

    const size_t total_len = METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH + size;
    char *full_buf = malloc(total_len);
    if (!full_buf) {
        free(buffer);
        return;
    }

    full_buf[0] = CONFIG_VERSION;
    full_buf[1] = RSV;
    full_buf[2] = STATUS_OK;
    const uint32_t body_len = htonl(size);
    memcpy(full_buf + METRICS_WRITE_HEADER_SIZE, &body_len, METRICS_WRITE_PAYLOAD_LENGTH);
    memcpy(full_buf + METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH, buffer, size);

    free(buffer);

    data->metrics_buf = full_buf;
    data->metrics_buf_len = total_len;
    data->metrics_buf_offset = 0;
}

void prepare_user_metrics_buffer(client_config_data *data, user_metrics *um) {
    char *buffer = NULL;
    size_t size = 0;

    FILE *memfile = open_memstream(&buffer, &size);
    if (!memfile) return;

    print_user_metrics_tabbed(um, data->target_username, memfile);
    fflush(memfile);
    fclose(memfile);

    const size_t total_len = METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH + size;
    char *full_buf = malloc(total_len);
    if (!full_buf) {
        free(buffer);
        return;
    }

    full_buf[0] = CONFIG_VERSION;
    full_buf[1] = RSV;
    full_buf[2] = STATUS_OK;
    const uint32_t body_len = htonl(size);
    memcpy(full_buf + METRICS_WRITE_HEADER_SIZE, &body_len, METRICS_WRITE_PAYLOAD_LENGTH);
    memcpy(full_buf + METRICS_WRITE_HEADER_SIZE + METRICS_WRITE_PAYLOAD_LENGTH, buffer, size);

    free(buffer);

    data->metrics_buf = full_buf;
    data->metrics_buf_len = total_len;
    data->metrics_buf_offset = 0;
}

unsigned attempt_admin_metrics_write(struct selector_key *key) {
    client_config_data *data = key->data;
    const int clnt_socket = key->fd;

    if (data->target_ulen == 0) {
        if (data->metrics_buf == NULL) {
            prepare_global_metrics_buffer(data);
            if (data->metrics_buf == NULL) return CONFIG_DONE;
        }
        return send_metrics_buffer(data, clnt_socket, ADMIN_METRICS_SEND);
    }

    user_metrics *um = get_or_create_user_metrics(data->target_username);
    if (!um) {
        log(ERROR, "User metrics not found for %s", data->target_username);
        return CONFIG_DONE;
    }
    if (data->metrics_buf == NULL) {
        prepare_user_metrics_buffer(data, um);
        if (data->metrics_buf == NULL) return CONFIG_DONE;
    }
    return send_metrics_buffer(data, clnt_socket, ADMIN_METRICS_SEND);
}

unsigned handle_admin_metrics_write(struct selector_key *key) {
    return send_metrics_buffer(key->data, key->fd, ADMIN_METRICS_SEND);
}
unsigned handle_user_metrics_write(struct selector_key *key) {
    return send_metrics_buffer(key->data, key->fd, USER_METRICS);
}

unsigned attempt_user_metrics_write(struct selector_key *key) {
    client_config_data *data = key->data;
    const int clnt_socket = key->fd;

    if (data->metrics_buf == NULL) {
        if (!prepare_user_metrics_buffer_from_auth(data)) {
            const uint8_t response[3] = { CONFIG_VERSION, RSV, STATUS_SERVER_GENERAL_FAILURE };
            buffer_reset(data->client_buffer);
            memcpy(data->client_buffer->write, response, METRICS_FAILURE_RESPONSE_SIZE);
            buffer_write_adv(data->client_buffer, METRICS_FAILURE_RESPONSE_SIZE);
            return send_metrics_fail_response(key);
        }
    }

    return send_metrics_buffer(data, clnt_socket, USER_METRICS);
}
