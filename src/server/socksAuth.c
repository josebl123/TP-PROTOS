//
// Created by nicol on 6/26/2025.
//

#include "socksAuth.h"
#include "../utils/logger.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>


unsigned handleHelloRead(struct selector_key *key) {
    // Aquí se manejaría la lectura del mensaje de saludo del cliente
      int clntSocket = key->fd; // Socket del cliente
    clientData *data = key->data;
    log(INFO, "hello Read");
    // Recibir mensaje del cliente
    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);
    buffer_write_adv(data->clientBuffer, numBytesRcvd);

    if (numBytesRcvd < 0) { //TODO en este caso que se hace? Libero todo?
        log(ERROR, "recv() failed on client socket %d", clntSocket);
        return ERROR_CLIENT; // TODO definir codigos de error
    }
     if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }
      const uint8_t socksVersion = buffer_read(data->clientBuffer);
      const uint8_t totalAuthMethods = buffer_read(data->clientBuffer);
        log(INFO, "Total methods: %d", totalAuthMethods); //sumo 1 porque es el segundo byte del saludo
      if( socksVersion == SOCKS_VERSION ){ //chequea que sea SOCKS5
        for(int i =0; i < totalAuthMethods; i++){
          if(buffer_read(data->clientBuffer) == AUTH_METHOD_PASSWORD){
			data->authMethod = AUTH_METHOD_PASSWORD;
            selector_set_interest_key(key, OP_WRITE);
            log(INFO, "Selected authentication method: Password");
            buffer_reset(data->clientBuffer);
            return HELLO_WRITE; // Cambiar al estado de escritura de saludo
          }
        }
        log(ERROR, "Unsupported authentication method or incomplete data");
        return HELLO_WRITE;
      }
        return ERROR_CLIENT; // TODO definir codigos de error


}
unsigned handleHelloWrite(struct selector_key *key) {
    const int clntSocket = key->fd; // Socket del cliente
    const clientData *data = key->data;

    // Enviar respuesta de saludo al cliente
    const uint8_t response[2] = {SOCKS_VERSION, data->authMethod}; // Respuesta de saludo con autenticación no requerida
    const ssize_t numBytesSent = send(clntSocket, response, sizeof(response), MSG_DONTWAIT);
    if (numBytesSent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) { //FIXME: recordar cuantos bytes se enviaron
            // No se pudo enviar por ahora, volver a intentar más tarde
            return HELLO_WRITE;
        }
        log(ERROR, "send() failed on client socket %d", clntSocket);
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }
        // Mensaje enviado correctamente, desregistrar el interés de escritura
    if ( sizeof(response) == numBytesSent) {
        selector_set_interest_key(key, OP_READ); // Cambiar interés a lectura para recibir autenticación
        log(INFO, "Sent hello response to client socket %d", clntSocket);
        return AUTH_READ;
    }
    log(INFO, "Sent %zd bytes of hello response to client socket %d", numBytesSent, clntSocket);
    return HELLO_WRITE; // Mantener el estado de escritura de saludo
}

unsigned handleAuthRead(struct selector_key *key) {
    // Aquí se manejaría la lectura del mensaje de autenticación del cliente
    int clntSocket = key->fd; // Socket del cliente
    clientData *data = key->data;
    log(INFO, "reading auth info");
    size_t writeLimit;
    uint8_t *readPtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, readPtr, writeLimit, 0);
    buffer_write_adv(data->clientBuffer, numBytesRcvd);
    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d", clntSocket);
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection ACA", clntSocket);
        return DONE;
    }
    int usernameLength ; // Longitud del nombre de usuario
    const uint8_t socksVersion = buffer_read(data->clientBuffer);
    if( socksVersion == SUBNEGOTIATION_VERSION && numBytesRcvd >= 2) { // Si el metodo de autenticacion es password y tengo al menos 2 bytes TODO magic nums
        usernameLength = buffer_read(data->clientBuffer); // Longitud del nombre de usuario
        log(INFO, "Username length: %d", usernameLength);
    } else {
        // Si no es SOCKS_VERSION o no tengo suficientes bytes, error
        log(ERROR, "Unsupported authentication method or incomplete data");
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if(numBytesRcvd < usernameLength + 2) { // Si no tengo suficientes bytes para el nombre de usuario
        log(ERROR, "Incomplete authentication data received");
        return AUTH_READ; // TODO definir codigos de error
    }
    strncpy( data->authInfo.username, (char *) data->clientBuffer->read, usernameLength); // Copio el nombre de usuario al buffer
    buffer_read_adv(data->clientBuffer, usernameLength); // Avanzo el puntero de lectura del buffer
    data->authInfo.username[usernameLength] = '\0'; // Asegurar que el nombre de usuario esté terminado en nulo
    log(INFO, "Received username: %s", data->authInfo.username);

    const int passwordLength = buffer_read(data->clientBuffer); // TODO: faltan chequeos de errores

    if( false ) { // TODO: este chequeo
        log(ERROR, "Incomplete authentication data received");
        return AUTH_READ; // TODO definir codigos de error
    }
    strncpy( data->authInfo.password,(char *) data->clientBuffer->read, passwordLength); // Copio el nombre de usuario al buffer
    buffer_read_adv(data->clientBuffer, passwordLength);// Avanzo el offset del buffer
    data->authInfo.password[passwordLength] = '\0'; // Asegurar que la contraseña esté terminada en nulo
    log(INFO, "Received password: %s", data->authInfo.password);
    selector_set_interest_key(key, OP_WRITE); // TODO: devuelve estado, chequear
    return AUTH_WRITE; // Cambiar al estado de escritura de autenticación

}

unsigned handleAuthWrite(struct selector_key *key) {
    int clntSocket = key->fd; // Socket del cliente
    clientData *data =  key->data;

    // Enviar respuesta de autenticación al cliente
    char response[2] = {SOCKS_VERSION, 1}; // Respuesta de autenticación exitosa FIXME: magic num
    if( strcmp(data->authInfo.username, "user") == 0 && strcmp(data->authInfo.password, "pass") == 0) {
        response[1] = 0; // Autenticación exitosa
    }
    const ssize_t numBytesSent = send(clntSocket, response, sizeof(response), MSG_DONTWAIT);

    log(INFO, "Sending authentication response to client socket %d with bytes: %zu", clntSocket, numBytesSent);

    if (numBytesSent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No se pudo enviar por ahora, volver a intentar más tarde
            return AUTH_WRITE;
        }
        log(ERROR, "send() failed on client socket %d", clntSocket);

        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (numBytesSent == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }

    if( response[1] != 0) { // Si la autenticación falló fixme: magic num
        log(ERROR, "Authentication failed for client socket %d", clntSocket);
        return ERROR_CLIENT; // TODO definir codigos de error
    }
    if (sizeof(response) == numBytesSent) {
        selector_set_interest_key(key, OP_READ); // Cambiar interés a lectura para recibir solicitud
        log(INFO, "Sent authentication response to client socket %d", clntSocket);
        return REQUEST_READ;
    }
    buffer_read_adv(data->clientBuffer, numBytesSent);
    return AUTH_WRITE;
}
