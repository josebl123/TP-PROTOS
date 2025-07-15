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

unsigned attemptHelloWrite(struct selector_key *key) {
    const clientData *data = key->data;
    buffer_reset(data->clientBuffer);
    buffer_write(data->clientBuffer, SOCKS_VERSION); // Versión del protocolo SOCKS
    buffer_write(data->clientBuffer, data->authMethod); // Método de autenticación seleccionado
    return handleHelloWrite(key); // Manejar la escritura del saludo

}
unsigned handleHelloRead(struct selector_key *key) {
    // Aquí se manejaría la lectura del mensaje de saludo del cliente
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = key->data;
    // Recibir mensaje del cliente
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    if (numBytesRcvd < 0) { //TODO en este caso que se hace? Libero todo?
        log(ERROR, "recv() failed on client socket %d", clntSocket);
        return ERROR_CLIENT;
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }
    buffer_write_adv(data->clientBuffer, numBytesRcvd);
    size_t readLimit;
    const uint8_t *ptr = buffer_read_ptr(data->clientBuffer, &readLimit);
    if (readLimit < AUTH_METHODS_START) { // Se necesitan al menos 2 bytes para la versión y el método de autenticación
        log(ERROR, "Insufficient data received for authentication");
        return HELLO_READ; // Esperar más datos
    }
    const uint8_t socksVersion = ptr[0];
    const uint8_t totalAuthMethods = ptr[1];
    if (readLimit < AUTH_METHODS_START + (size_t)totalAuthMethods) { // Chequear que se recibieron todos los métodos de autenticación
        log(ERROR, "Insufficient data received for authentication methods");
        return HELLO_READ; // Esperar más datos
    }
    buffer_read_adv(data->clientBuffer, AUTH_METHODS_START);
    if( socksVersion == SOCKS_VERSION ){
        bool clientAcceptsNoAuth = false;
        //chequea que sea SOCKS5
        for(int i =0; i < totalAuthMethods; i++){
            const int authMethod = buffer_read(data->clientBuffer); // Lee el método de autenticación
            if(authMethod == AUTH_METHOD_PASSWORD){
			    data->authMethod = AUTH_METHOD_PASSWORD;
                if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {;
                    log(ERROR, "Failed to set interest for client socket %d", clntSocket);
                    return ERROR_CLIENT;
                }
                buffer_reset(data->clientBuffer);
                return attemptHelloWrite(key); // Cambiar al estado de escritura de saludo
            }
            if (authMethod == AUTH_METHOD_NOAUTH) {
                clientAcceptsNoAuth = true; // Si acepta autenticación sin contraseña
            }
        }
        if (socksArgs->serverAcceptsNoAuth && clientAcceptsNoAuth) {
            data->authMethod = AUTH_METHOD_NOAUTH;
            buffer_reset(data->clientBuffer);
            metrics_new_connection(); // Registrar nueva conexión anónima
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {;
                log(ERROR, "Failed to set interest for client socket %d", clntSocket);
                return ERROR_CLIENT;
            }
            return attemptHelloWrite(key); // Cambiar al estado de escritura de saludo
        }
        log(ERROR, "Unsupported authentication method or incomplete data");
        add_new_login_error();
        data->authMethod = NO_ACCEPTABLE_METHODS;
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", clntSocket);
            return ERROR_CLIENT;
        }
        return attemptHelloWrite(key);
    }
    return ERROR_CLIENT;
}

unsigned handleHelloWrite(struct selector_key *key) {
    const clientData *data = key->data;
    const unsigned toReturn = genericWrite(key,data->authMethod == AUTH_METHOD_NOAUTH ? REQUEST_READ : AUTH_READ , HELLO_WRITE);
    if (toReturn == REQUEST_READ || toReturn == AUTH_READ) {
        if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            return ERROR_CLIENT; // Error al cambiar el interés a lectura
        }
    }
    return toReturn; // Retorna el estado al que se debe cambiar
}

unsigned attemptAuthWrite(struct selector_key *key) {
    clientData *data = key->data;
    buffer_reset(data->clientBuffer);
    buffer_write(data->clientBuffer, SOCKS_VERSION); // Versión del protocolo SOCKS
    bool success=0;
    for (int i=0; i < MAX_USERS && socksArgs->users[i].name != NULL; i++) {
        if (strcmp(socksArgs->users[i].name, data->authInfo.username) == 0 &&
            strcmp(socksArgs->users[i].pass, data->authInfo.password) == 0) {
            data->isAnonymous = 0;
            success =1;
            metrics_new_connection(); // Actualiza las métricas por nueva conexión
            break; // Salir del bucle si la autenticación es exitosa
            }
    }
    if (success) {
        buffer_write(data->clientBuffer,  AUTH_SUCCESS); // Autenticación exitosa
    } else {
        add_new_login_error();
        buffer_write(data->clientBuffer, AUTH_FAILURE); // Autenticación fallida
    }


    return handleAuthWrite(key); // Manejar la escritura de autenticación
}

unsigned handleAuthRead(struct selector_key *key) {
    // Aquí se manejaría la lectura del mensaje de autenticación del cliente
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = key->data;
    size_t writeLimit;
    uint8_t *readPtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, readPtr, writeLimit, 0);
    if (numBytesRcvd < 0) {
        return ERROR_CLIENT;
    }
    if (numBytesRcvd == 0) {
        return DONE;
    }
    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    size_t readLimit;
    const uint8_t *ptr = buffer_read_ptr(data->clientBuffer, &readLimit);
    if (readLimit < USERNAME_START) { // Se necesitan al menos 2 bytes para la versión y el método de autenticación
        log(ERROR, "Insufficient data received for authentication");
        return AUTH_READ; // Esperar más datos
    }
    const uint8_t authVersion = ptr[0]; // Leer la versión de autenticación
    const uint8_t usernameLength  = ptr[1];


    if (authVersion != SUBNEGOTIATION_VERSION) {
        // Si no es SOCKS_VERSION o no tengo suficientes bytes, error
        log(ERROR, "Unsupported authentication method or incomplete data");
        return ERROR_CLIENT;
    }
    if (usernameLength <= 0 || usernameLength > MAX_USERNAME_LEN) { // Chequear longitud del nombre de usuario
        log(ERROR, "Invalid username length: %d", usernameLength);
        return ERROR_CLIENT;
    }

    if (readLimit < (size_t)usernameLength + USERNAME_START + PASSWORD_START) { // Si no tengo suficientes bytes para el nombre de usuario
        log(ERROR, "Insufficient data received for username");
        return AUTH_READ;
    }
    const uint8_t passwordLength = ptr[ USERNAME_START + usernameLength]; // Leer la longitud de la contraseña
    if (passwordLength <= 0 || passwordLength > MAX_PASSWORD_LEN) { // Chequear longitud de la contraseña
        log(ERROR, "Invalid password length: %d", passwordLength);
        return ERROR_CLIENT;
    }

    if (readLimit < USERNAME_START + (size_t)passwordLength + usernameLength + PASSWORD_START ) { // Si no tengo suficientes bytes para la contraseña
        log(ERROR, "Insufficient data received for password");
        return AUTH_READ;
    }

    buffer_read_adv(data->clientBuffer, USERNAME_START); // authVersion + usernameLength

    strncpy( data->authInfo.username, (char*)buffer_read_ptr(data->clientBuffer,&readLimit), usernameLength); // Copio el nombre de usuario al buffer
    buffer_read_adv(data->clientBuffer, usernameLength); // Avanzo el puntero de lectura del buffer
    data->authInfo.username[usernameLength] = '\0'; // Asegurar que el nombre de usuario esté terminado en nulo

    buffer_read_adv(data->clientBuffer, PASSWORD_START); // authVersion + usernameLength

    strncpy( data->authInfo.password,(char *) buffer_read_ptr(data->clientBuffer,&readLimit), passwordLength); // Copio el nombre de usuario al buffer
    buffer_read_adv(data->clientBuffer, passwordLength);// Avanzo el offset del buffer
    data->authInfo.password[passwordLength] = '\0'; // Asegurar que la contraseña esté terminada en nulo
     if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
         log(ERROR, "Failed to set interest for client socket %d", clntSocket);
         return ERROR_CLIENT;
     }
    return attemptAuthWrite(key); // Cambiar al estado de escritura de autenticación
}


unsigned handleAuthWrite(struct selector_key *key) {
    clientData *data = key->data;

    const unsigned next_state = genericWrite(key,  REQUEST_READ,AUTH_WRITE);
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
