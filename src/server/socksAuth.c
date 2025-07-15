//
// Created by nicol on 6/26/2025.
//

#include "socksAuth.h"

#include <args.h>

#include "../utils/logger.h"
#include <errno.h>
#include "server/server.h"
#include <string.h>
#include <sys/socket.h>

#include <time.h>
#include "../metrics/metrics.h"
#include "serverConfigActions.h"

#define USERNAME_START 2 // Offset for username in authentication subnegotiation
#define PASSWORD_START 1 // Offset for password in authentication subnegotiation
#define AUTH_METHODS_START 2 // Offset for authentication methods in the hello message

unsigned attempt_hello_write(struct selector_key *key) {
    const client_data *data = key->data;
    buffer_reset(data->client_buffer);
    buffer_write(data->client_buffer, SOCKS_VERSION); // Versión del protocolo SOCKS
    buffer_write(data->client_buffer, data->auth_method); // Método de autenticación seleccionado
    return handle_hello_write(key); // Manejar la escritura del saludo

}
unsigned handle_hello_read(struct selector_key *key) {
    // Aquí se manejaría la lectura del mensaje de saludo del cliente
    int clnt_socket = key->fd; // Socket del cliente
    client_data *data = key->data;
    // Recibir mensaje del cliente
    size_t write_limit;
    uint8_t *write_ptr = buffer_write_ptr(data->client_buffer, &write_limit);
    const ssize_t num_bytes_rcvd = recv(clnt_socket, write_ptr, write_limit, 0);
    if (num_bytes_rcvd < 0) {
        log(ERROR, "recv() failed on client socket %d", clnt_socket);
        return ERROR_CLIENT;
    }
    if (num_bytes_rcvd == 0) {
        log(INFO, "Client socket %d closed connection", clnt_socket);
        return DONE;
    }
    buffer_write_adv(data->client_buffer, num_bytes_rcvd);
    size_t read_limit;
    const uint8_t *ptr = buffer_read_ptr(data->client_buffer, &read_limit);
    if (read_limit < AUTH_METHODS_START) { // Se necesitan al menos 2 bytes para la versión y el método de autenticación
        log(ERROR, "Insufficient data received for authentication");
        return HELLO_READ; // Esperar más datos
    }
    const uint8_t socks_version = ptr[0];
    const uint8_t total_auth_methods = ptr[1];
    if (read_limit < AUTH_METHODS_START + (size_t)total_auth_methods) { // Chequear que se recibieron todos los métodos de autenticación
        log(ERROR, "Insufficient data received for authentication methods");
        return HELLO_READ; // Esperar más datos
    }
    buffer_read_adv(data->client_buffer, AUTH_METHODS_START);
    if( socks_version == SOCKS_VERSION ){
        bool client_accepts_no_auth = false;
        //chequea que sea SOCKS5
        for(int i =0; i < total_auth_methods; i++){
            const int auth_method = buffer_read(data->client_buffer); // Lee el método de autenticación
            if(auth_method == AUTH_METHOD_PASSWORD){
			    data->auth_method = AUTH_METHOD_PASSWORD;
                if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {;
                    log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
                    return ERROR_CLIENT;
                }
                buffer_reset(data->client_buffer);
                return attempt_hello_write(key); // Cambiar al estado de escritura de saludo
            }
            if (auth_method == AUTH_METHOD_NOAUTH) {
                client_accepts_no_auth = true; // Si acepta autenticación sin contraseña
            }
        }
        if (socks_args->server_accepts_no_auth && client_accepts_no_auth) {
            data->auth_method = AUTH_METHOD_NOAUTH;
            buffer_reset(data->client_buffer);
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {;
                log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
                return ERROR_CLIENT;
            }
            return attempt_hello_write(key); // Cambiar al estado de escritura de saludo
        }
        log(ERROR, "Unsupported authentication method or incomplete data");
        add_new_login_error();
        data->auth_method = NO_ACCEPTABLE_METHODS;
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
            return ERROR_CLIENT;
        }
        return attempt_hello_write(key);
    }
    return ERROR_CLIENT;
}

unsigned handle_hello_write(struct selector_key *key) {
    const client_data *data = key->data;
    const unsigned to_return = generic_write(key,data->auth_method == AUTH_METHOD_NOAUTH ? REQUEST_READ : AUTH_READ , HELLO_WRITE);
    if (to_return == REQUEST_READ || to_return == AUTH_READ) {
        if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            return ERROR_CLIENT; // Error al cambiar el interés a lectura
        }
    }
    return to_return; // Retorna el estado al que se debe cambiar
}

unsigned attempt_auth_write(struct selector_key *key) {
    client_data *data = key->data;
    buffer_reset(data->client_buffer);
    buffer_write(data->client_buffer, SOCKS_VERSION); // Versión del protocolo SOCKS
    bool success=0;
    for (int i=0; i < MAX_USERS && socks_args->users[i].name != NULL; i++) {
        if (strcmp(socks_args->users[i].name, data->auth_info.username) == 0 &&
            strcmp(socks_args->users[i].pass, data->auth_info.password) == 0) {
            data->is_anonymous = 0;
            success =1;
            break; // Salir del bucle si la autenticación es exitosa
            }
    }
    if (success) {
        buffer_write(data->client_buffer,  AUTH_SUCCESS); // Autenticación exitosa
    } else {
        add_new_login_error();
        buffer_write(data->client_buffer, AUTH_FAILURE); // Autenticación fallida
    }


    return handle_auth_write(key); // Manejar la escritura de autenticación
}

unsigned handle_auth_read(struct selector_key *key) {
    // Aquí se manejaría la lectura del mensaje de autenticación del cliente
    int clnt_socket = key->fd; // Socket del cliente
    client_data *data = key->data;
    size_t write_limit;
    uint8_t *read_ptr = buffer_write_ptr(data->client_buffer, &write_limit);
    const ssize_t num_bytes_rcvd = recv(clnt_socket, read_ptr, write_limit, 0);
    if (num_bytes_rcvd < 0) {
        return ERROR_CLIENT;
    }
    if (num_bytes_rcvd == 0) {
        return DONE;
    }
    buffer_write_adv(data->client_buffer, num_bytes_rcvd);

    size_t read_limit;
    const uint8_t *ptr = buffer_read_ptr(data->client_buffer, &read_limit);
    if (read_limit < USERNAME_START) { // Se necesitan al menos 2 bytes para la versión y el método de autenticación
        log(ERROR, "Insufficient data received for authentication");
        return AUTH_READ; // Esperar más datos
    }
    const uint8_t auth_version = ptr[0]; // Leer la versión de autenticación
    const uint8_t username_length  = ptr[1];


    if (auth_version != SUBNEGOTIATION_VERSION) {
        // Si no es SOCKS_VERSION o no tengo suficientes bytes, error
        log(ERROR, "Unsupported authentication method or incomplete data");
        return ERROR_CLIENT;
    }
    if (username_length <= 0 || username_length > MAX_USERNAME_LEN) { // Chequear longitud del nombre de usuario
        log(ERROR, "Invalid username length: %d", username_length);
        return ERROR_CLIENT;
    }

    if (read_limit < (size_t)username_length + USERNAME_START + PASSWORD_START) { // Si no tengo suficientes bytes para el nombre de usuario
        log(ERROR, "Insufficient data received for username");
        return AUTH_READ;
    }
    const uint8_t password_length = ptr[ USERNAME_START + username_length]; // Leer la longitud de la contraseña
    if (password_length <= 0 || password_length > MAX_PASSWORD_LEN) { // Chequear longitud de la contraseña
        log(ERROR, "Invalid password length: %d", password_length);
        return ERROR_CLIENT;
    }

    if (read_limit < USERNAME_START + (size_t)password_length + username_length + PASSWORD_START ) { // Si no tengo suficientes bytes para la contraseña
        log(ERROR, "Insufficient data received for password");
        return AUTH_READ;
    }

    buffer_read_adv(data->client_buffer, USERNAME_START); // auth_version + username_length

    strncpy( data->auth_info.username, (char*)buffer_read_ptr(data->client_buffer,&read_limit), username_length); // Copio el nombre de usuario al buffer
    buffer_read_adv(data->client_buffer, username_length); // Avanzo el puntero de lectura del buffer
    data->auth_info.username[username_length] = '\0'; // Asegurar que el nombre de usuario esté terminado en nulo

    buffer_read_adv(data->client_buffer, PASSWORD_START); // auth_version + username_length

    strncpy( data->auth_info.password,(char *) buffer_read_ptr(data->client_buffer,&read_limit), password_length); // Copio el nombre de usuario al buffer
    buffer_read_adv(data->client_buffer, password_length);// Avanzo el offset del buffer
    data->auth_info.password[password_length] = '\0'; // Asegurar que la contraseña esté terminada en nulo
     if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
         log(ERROR, "Failed to set interest for client socket %d", clnt_socket);
         return ERROR_CLIENT;
     }
    return attempt_auth_write(key); // Cambiar al estado de escritura de autenticación
}


unsigned handle_auth_write(struct selector_key *key) {
    client_data *data = key->data;

    const unsigned next_state = generic_write(key,  REQUEST_READ,AUTH_WRITE);
    if (next_state == AUTH_WRITE) {
        data->current_user_conn.access_time = time(NULL);
        return AUTH_WRITE;
    }
    if (next_state == REQUEST_READ) {
        if ( selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            return ERROR_CLIENT; // Error al cambiar el interés a lectura
        }
    }
    return next_state;

}
