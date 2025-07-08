//
// Created by nicol on 7/7/2025.
//

#include "clientConfig.h"
#include "args.h"
#include "logger.h"
#include "client.h"
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

enum OPTIONS {
    OPTION_BUFFER_SIZE = 0x00, // Read or write buffer size
    OPTION_ACCEPTS_NO_AUTH = 0x01, // Read configuration
    OPTION_NOT_ACCEPTS_NO_AUTH = 0x02, // Write configuration
    OPTION_ADD_USER = 0x03, // Read stats
    OPTION_REMOVE_USER = 0x04, // Done with configuration
    OPTION_MAKE_ADMIN = 0x05, // Make user admin
};


unsigned handleConfigRead(struct selector_key *key){
    clientData *data = key->data;
    int clntSocket = key->fd; // Socket del cliente

    log(INFO, "Reading request from client socket %d", clntSocket);

    size_t writeLimit;
    uint8_t *writePtr = buffer_write_ptr(data->clientBuffer, &writeLimit);
    const ssize_t numBytesRcvd = recv(clntSocket, writePtr, writeLimit, 0);

    if (numBytesRcvd < 0) {
        log(ERROR, "recv() failed on client socket %d: %s", clntSocket, strerror(errno));
        return ERROR_CLIENT; // TODO definir codigos de error
    }

    if (numBytesRcvd == 0) {
        log(INFO, "Client socket %d closed connection", clntSocket);
        return DONE;
    }
    if(buffer_read(data->clientBuffer) != VERSION) {
        log(ERROR, "Invalid version in authentication request from client socket %d", clntSocket);
        return ERROR_CLIENT; // Abortamos si la versión no es correcta
    }
    if (buffer_read(data->clientBuffer) != RSV) {
        log(ERROR, "Invalid reserved byte in authentication request from client socket %d", clntSocket);
        return ERROR_CLIENT; // Abortamos si el byte reservado no es correcto
    }
    if( buffer_read(data->clientBuffer) == 0x00) {
        log(INFO, "SUCCESS");
        return DONE; // Abortamos si la opción no es válida

    }
    log(ERROR, "Config change failed");
    return DONE; // Si no es un estado válido, abortamos
  }

unsigned handleConfigWrite(struct selector_key *key){
    const int clntSocket = key->fd; // Socket del cliente
    struct clientData *data = key->data; // Datos del cliente
    char * response;

    switch (data->args->type) {
       case BUFFER_SIZE:
           response = calloc(11,1);
           response[0] = VERSION; // Version for configuration
           response[1] = RSV; // Reserved byte for configuration
           response[2] = OPTION_BUFFER_SIZE; // Option for buffer size
           response[7] = data->args->buffer_size >> 24; // High byte
           response[8] = data->args->buffer_size >> 16; // Middle high byte
           response[9] = data->args->buffer_size >> 8; // Middle low byte
           response[10] = data->args->buffer_size & 0xFF; // Low byte

         break;
       case ACCEPTS_NO_AUTH: // If the client accepts no authentication
            response = calloc(8,1);
            response[0] = VERSION; // Version for configuration
            response[1] = RSV; // Reserved byte for configuration
            response[2] = data->args->accepts_no_auth ? OPTION_ACCEPTS_NO_AUTH : OPTION_NOT_ACCEPTS_NO_AUTH; // Option for accepts no auth
            break;

  case ADD_USER:
    response = calloc(5 + strlen(data->args->user.name) + strlen(data->args->user.pass), 1);
            response[0] = VERSION; // Version for configuration
            response[1] = RSV; // Reserved byte for configuration
            response[2] = OPTION_ADD_USER; // Option for adding user
            response[3] = strlen(data->args->user.name); // Length of username
            memcpy(response + 4, data->args->user.name, strlen(data->args->user.name)); // Copy username
            response[4 + strlen(data->args->user.name) ] = strlen(data->args->user.pass); // Length of password
            memcpy(response + 5 + strlen(data->args->user.name), data->args->user.pass, strlen(data->args->user.pass)); // Copy password
         break;
   case REMOVE_USER: // If the client removes a user
            response = calloc(5 + strlen(data->args->user.name), 1);
                response[0] = VERSION; // Version for configuration
                response[1] = RSV; // Reserved byte for configuration
                response[2] = OPTION_REMOVE_USER; // Option for removing user
                response[3] = strlen(data->args->user.name); // Length of username
                memcpy(response + 4, data->args->user.name, strlen(data->args->user.name)); // Copy username
            break;
  case MAKE_ADMIN: // If the client adds an admin
            response = calloc(5 + strlen(data->args->user.name), 1);
            response[0] = VERSION; // Version for configuration
            response[1] = RSV; // Reserved byte for configuration
            response[2] = OPTION_MAKE_ADMIN; // Option for making user admin
            response[3] = strlen(data->args->user.name); // Length of username
            memcpy(response + 4, data->args->user.name, strlen(data->args->user.name)); // Copy username
            break;
  default:
            log(ERROR, "Unknown configuration option: %d", data->args->type);
            free(response);
            return ERROR_CLIENT; // Abortamos si la opción no es válida

     }
    ssize_t sent = send(clntSocket, response, strlen(response), 0);
    if( sent < 0) {
        log(ERROR, "send() failed on client socket %d: %s", clntSocket, strerror(errno));
        free(response);
        return ERROR_CLIENT; // Abortamos si hubo error al enviar
    }
    if (sent == 0) {
        log(INFO, "Closed");
        free(response);
        return DONE;
    }

    free(response);
    selector_set_interest_key(key, OP_READ); // Desregistrar el socket del selector
    return CONFIG_READ; // Cambia

 }




