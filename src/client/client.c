//
// Created by nicol on 6/24/2025.
//
#define TRUE   1
#define FALSE  0
#define INITIAL_MAX_CLIENTS 500

#include "client.h"
#include "args.h"
#include "tcpClientUtil.h"
#include "clientAuth.h"
#include "clientRequest.h"
#include "clientConfig.h"
#include "../utils/logger.h"
#include "../selector.h"
#include "../buffer.h"

#include <stdio.h>
#include <signal.h>
#include <unistd.h>   //close
#include <errno.h>

#define BUFFER_SIZE 1024 // Define a buffer size for client communication
static const struct state_definition states[] = {
  [AUTH_READ] =     { .state = AUTH_READ, .on_read_ready = handleAuthRead },
  [AUTH_WRITE] =    { .state = AUTH_WRITE, .on_write_ready = handleAuthWrite },
  [REQUEST_READ] =  { .state = REQUEST_READ, .on_read_ready = handleRequestRead },
  [REQUEST_WRITE] = { .state = REQUEST_WRITE, .on_write_ready = handleRequestWrite },
  [DONE] =          { .state = DONE, /*.on_arrival = clientClose */ },
  [STATS_READ]= {.state = STATS_READ, .on_read_ready = handleStatsRead},
  [ERROR_CLIENT] =  { .state = ERROR_CLIENT,/*.on_arrival = clientClose*/},
  [CONFIG_READ] =   { .state = CONFIG_READ, .on_read_ready = handleConfigRead },
  [CONFIG_WRITE] =  { .state = CONFIG_WRITE, .on_write_ready = handleConfigWrite },
};

int main(int argc, char** argv) {
  struct clientArgs client_args;
  parse_client_args(argc, argv, &client_args);
  clientData *data = malloc(sizeof(clientData));
  struct state_machine *stm = malloc(sizeof(struct state_machine));
  if (stm == NULL) {
    perror("Failed to allocate memory for state machine");
    exit(EXIT_FAILURE);
  }
  stm->initial = AUTH_WRITE; // Initial state for client authentication
  stm->states = states;
  stm->max_state = ERROR_CLIENT; // Total number of states
  stm_init(stm);
  data->stm = stm; // Assign the state machine to client data
  buffer *buf = malloc(sizeof(buffer));
  if (buf == NULL) {
    perror("Failed to allocate memory for buffer");
    free(stm);
    free(data);
    return -1;
  }
  buf->data = malloc(BUFFER_SIZE * sizeof(char)); // Allocate buffer data
  if (buf->data == NULL) {
    perror("Failed to allocate memory for buffer data");
    free(buf);
    free(stm);
    free(data);

    return -1;
  }
  buffer_init(buf, BUFFER_SIZE, buf->data); // Initialize the buffer
  data->clientBuffer = buf; // Assign the buffer to client data
  const struct selector_init conf = {
    .signal = SIGUSR1,
    .select_timeout = { .tv_sec = 5, .tv_nsec = 0 } //TODO: esto es un timeout de 5 segundos, esta bien?
  };
  const selector_status status = selector_init(&conf);
  if(status != SELECTOR_SUCCESS) {
    perror("Failed to initialize selector");
    exit(EXIT_FAILURE);
  }
  struct fdselector * selector = selector_new(INITIAL_MAX_CLIENTS);
  data->args = &client_args; // Assign the client arguments to client data


  const int socket = tcpClientSocket(client_args.addr, client_args.port);
  selector_register(selector, socket, &(fd_handler){
      .handle_read =  client_read, // funcion para crear sockets activos
      .handle_write = client_write,
      .handle_close = client_close,
  }, OP_WRITE, data);

  if (selector_fd_set_nio(socket) == -1) {
    close(socket);
    perror("Failed to set master socket to non-blocking mode");
    exit(EXIT_FAILURE);
  } // para que no bloquee
  while( TRUE){
    const int activity = selector_select(selector);

    if (activity < 0 && errno!=EINTR)
    {
      printf("select error");
    }
    }

}