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

#include "utils/user_metrics_table.h"
#include <time.h>
#include "../metrics/metrics.h"


unsigned handleHelloRead(struct selector_key *key) {
    // Aquí se manejaría la lectura del mensaje de saludo del cliente
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = key->data;
    // Recibir mensaje del cliente
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    buffer_write_adv(data->clientBuffer, numBytesRcvd);
    bool clientAcceptsNoAuth = false;
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d", clntSocket);
        return ERROR_CLIENT;
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }
    const uint8_t socksVersion = buffer_read(data->clientBuffer);
    const uint8_t totalAuthMethods = buffer_read(data->clientBuffer);
    if( socksVersion == SOCKS_VERSION ){ //chequea que sea SOCKS5
        for(int i =0; i < totalAuthMethods; i++){
            const int authMethod = buffer_read(data->clientBuffer); // Lee el método de autenticación
            if(authMethod == AUTH_METHOD_PASSWORD){
			    data->authMethod = AUTH_METHOD_PASSWORD;
                selector_set_interest_key(key, OP_WRITE);
                buffer_reset(data->clientBuffer);
                return HELLO_WRITE; // Cambiar al estado de escritura de saludo
            }
            if (authMethod == AUTH_METHOD_NOAUTH) {
                clientAcceptsNoAuth = true; // Si acepta autenticación sin contraseña
            }
        }
        if (socksArgs->serverAcceptsNoAuth && clientAcceptsNoAuth) {
            data->authMethod = AUTH_METHOD_NOAUTH;
            buffer_reset(data->clientBuffer);
            selector_set_interest_key(key, OP_WRITE);
            return HELLO_WRITE; // Cambiar al estado de escritura de saludo
        }
        log(ERROR, "Unsupported authentication method or incomplete data");
        data->authMethod = NO_ACCEPTABLE_METHODS;
        selector_set_interest_key(key, OP_WRITE); // Cambiar interés a escritura para enviar error
        return HELLO_WRITE;
    }
    return ERROR_CLIENT;


}
unsigned handleHelloWrite(struct selector_key *key) {
    const int clntSocket = key->fd; // Socket del cliente
    const clientData *data = key->data;

    // Enviar respuesta de saludo al cliente
    const uint8_t response[2] = {SOCKS_VERSION, data->authMethod}; // Respuesta de saludo con autenticación no requerida
    const ssize_t numBytesSent = send(clntSocket, response, sizeof(response), 0);
    if (numBytesSent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) { //FIXME: recordar cuantos bytes se enviaron
            // No se pudo enviar por ahora, volver a intentar más tarde
            return HELLO_WRITE;
        }
        log(ERROR, "send() failed on client socket %d", clntSocket);
        return ERROR_CLIENT;
    }
    if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }
        // Mensaje enviado correctamente, desregistrar el interés de escritura
    if ( sizeof(response) == numBytesSent) {
        selector_set_interest_key(key, OP_READ); // Cambiar interés a lectura para recibir autenticación
        if (data->authMethod == AUTH_METHOD_NOAUTH) {
            log(INFO, "No authentication required, moving to request read state");
            metrics_new_connection();
            return REQUEST_READ; // Si no se requiere autenticación, pasar al estado de lectura de solicitud
        }
        if (data->authMethod == AUTH_METHOD_PASSWORD) {
            log(INFO, "Selected authentication method: Password, moving to auth method subnegotiation");
            return AUTH_READ;
        }

        log(INFO, "No acceptable method for auth, moving back to hello read");
        return HELLO_READ;

    }
    return HELLO_WRITE; // Mantener el estado de escritura de saludo
}

unsigned handleAuthRead(struct selector_key *key) {
    // Aquí se manejaría la lectura del mensaje de autenticación del cliente
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = key->data;
    size_t writeLimit;
    uint8_t *readPtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    ssize_t numBytesRcvd = recv(clntSocket, readPtr, writeLimit, 0);
    buffer_write_adv(data->clientBuffer, numBytesRcvd);
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d", clntSocket);
        return ERROR_CLIENT;
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection ACA", clntSocket);
        return DONE;
    }
    int usernameLength = 0; // Longitud del nombre de usuario
    const uint8_t authVersion = buffer_read(data->clientBuffer);

    if (authVersion != SUBNEGOTIATION_VERSION) {
        // Si no es SOCKS_VERSION o no tengo suficientes bytes, error
        log(ERROR, "Unsupported authentication method or incomplete data");
        return ERROR_CLIENT;
    }
    numBytesRcvd--;
    usernameLength = buffer_read(data->clientBuffer);
    if (usernameLength <= 0 || usernameLength > MAX_USERNAME_LEN) { // Chequear longitud del nombre de usuario
        log(ERROR, "Invalid username length: %d", usernameLength);
        return ERROR_CLIENT;
    }
    numBytesRcvd--;
    numBytesRcvd -= usernameLength;

    if (numBytesRcvd < 0) { // Si no tengo suficientes bytes para el nombre de usuario
        log(ERROR, "Insufficient data received for username");
        return AUTH_READ;
    }

    strncpy( data->authInfo.username, (char *) data->clientBuffer->read, usernameLength); // Copio el nombre de usuario al buffer
    buffer_read_adv(data->clientBuffer, usernameLength); // Avanzo el puntero de lectura del buffer
    data->authInfo.username[usernameLength] = '\0'; // Asegurar que el nombre de usuario esté terminado en nulo

    const int passwordLength = buffer_read(data->clientBuffer);
    if (passwordLength <= 0 || passwordLength > MAX_PASSWORD_LEN) { // Chequear longitud de la contraseña
        log(ERROR, "Invalid password length: %d", passwordLength);
        return ERROR_CLIENT;
    }
    numBytesRcvd--;
    numBytesRcvd -= passwordLength;

    if (numBytesRcvd < 0) { // Si no tengo suficientes bytes para la contraseña
        log(ERROR, "Insufficient data received for password");
        return AUTH_READ;
    }

    strncpy( data->authInfo.password,(char *) data->clientBuffer->read, passwordLength); // Copio el nombre de usuario al buffer
    buffer_read_adv(data->clientBuffer, passwordLength);// Avanzo el offset del buffer
    data->authInfo.password[passwordLength] = '\0'; // Asegurar que la contraseña esté terminada en nulo
    selector_set_interest_key(key, OP_WRITE);
    return AUTH_WRITE; // Cambiar al estado de escritura de autenticación

//    if( authVersion == SUBNEGOTIATION_VERSION && numBytesRcvd >= 2) { // Si el metodo de autenticacion es password y tengo al menos 2 bytes TODO magic nums
//        usernameLength = buffer_read(data->clientBuffer); // Longitud del nombre de usuario
//    } else {
//        // Si no es SOCKS_VERSION o no tengo suficientes bytes, error
//        log(ERROR, "Unsupported authentication method or incomplete data");
//        return ERROR_CLIENT;
//    }
//    if(numBytesRcvd < usernameLength + 2) { // Si no tengo suficientes bytes para el nombre de usuario
//        return AUTH_READ;
//    }
//    strncpy( data->authInfo.username, (char *) data->clientBuffer->read, usernameLength); // Copio el nombre de usuario al buffer
//    buffer_read_adv(data->clientBuffer, usernameLength); // Avanzo el puntero de lectura del buffer
//    data->authInfo.username[usernameLength] = '\0'; // Asegurar que el nombre de usuario esté terminado en nulo
//
//    const int passwordLength = buffer_read(data->clientBuffer); // TODO: faltan chequeos de errores
//
//    if( false ) { // TODO: este chequeo
//        return AUTH_READ; // TODO definir codigos de error
//    }
//    strncpy( data->authInfo.password,(char *) data->clientBuffer->read, passwordLength); // Copio el nombre de usuario al buffer
//    buffer_read_adv(data->clientBuffer, passwordLength);// Avanzo el offset del buffer
//    data->authInfo.password[passwordLength] = '\0'; // Asegurar que la contraseña esté terminada en nulo
//    selector_set_interest_key(key, OP_WRITE); // TODO: devuelve estado, chequear
//    return AUTH_WRITE; // Cambiar al estado de escritura de autenticación
}

unsigned handleAuthWrite(struct selector_key *key) {
    const int clntSocket = key->fd; // Socket del cliente
    clientData *data =  key->data;

    // Enviar respuesta de autenticación al cliente
    char response[2] = {SOCKS_VERSION, AUTH_FAILURE}; // Respuesta de autenticación exitosa
    for (int i=0; i < MAX_USERS && socksArgs->users[i].name != NULL; i++) {
        if (strcmp(socksArgs->users[i].name, data->authInfo.username) == 0 &&
            strcmp(socksArgs->users[i].pass, data->authInfo.password) == 0) {
            response[1] = AUTH_SUCCESS; // Autenticación exitosa
            log(INFO, "Authentication successful for user: %s", data->authInfo.username);
            data->isAnonymous = 0;
            metrics_new_connection(); // Actualiza las métricas por nueva conexión
            break; // Salir del bucle si la autenticación es exitosa
            }
    }

    const ssize_t numBytesSent = send(clntSocket, response, sizeof(response), 0);

    if (numBytesSent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            return AUTH_WRITE;
        }
        log(ERROR, "send() failed on client socket %d", clntSocket);

        return ERROR_CLIENT;
    }
    if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }

    if( response[1] != AUTH_SUCCESS) { // Si la autenticación falló
        log(ERROR, "Authentication failed for client socket %d", clntSocket);
        add_new_login_error();
        return ERROR_CLIENT;
    }
    if (sizeof(response) == numBytesSent) {
        selector_set_interest_key(key, OP_READ); // Cambiar interés a lectura para recibir solicitud
        log(INFO, "Sent authentication response to client socket %d", clntSocket);
        return REQUEST_READ;
    }
    buffer_read_adv(data->clientBuffer, numBytesSent);
    data->current_user_conn.access_time = time(NULL);
    data->current_user_conn.port_origin = data->origin.port;
    fill_ip_address_from_origin(&data->current_user_conn.ip_origin, &data->origin);

    return AUTH_WRITE;
}
