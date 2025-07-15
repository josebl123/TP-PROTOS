//
// Created by nicol on 6/24/2025.
//
#define TRUE   1
#define FALSE  0

#include "client.h"
#include "args.h"
#include "tcpClientUtil.h"
#include "clientAuth.h"
#include "clientRequest.h"
#include "clientConfig.h"
#include "../utils/logger.h"
#include "../buffer.h"

#include <stdio.h>
#include <signal.h>
#include <unistd.h>   //close
#include <errno.h>

#define BUFFER_SIZE (1024  * 32) // Define a buffer size for client communication

int clnt_socket; // Global socket variable

int main(int argc, char** argv) {
  struct clientArgs client_args;
  parse_client_args(argc, argv, &client_args);
  client_data *data = malloc(sizeof(client_data));

  buffer *buf = malloc(sizeof(buffer));
  if (buf == NULL) {
    perror("Failed to allocate memory for buffer");
    free(data);
    return -1;
  }
  buf->data = malloc(BUFFER_SIZE * sizeof(char)); // Allocate buffer data
  if (buf->data == NULL) {
    perror("Failed to allocate memory for buffer data");
    free(buf);
    free(data);

    return -1;
  }
  buffer_init(buf, BUFFER_SIZE, buf->data); // Initialize the buffer
  data->client_buffer = buf; // Assign the buffer to client data

  data->args = &client_args; // Assign the client arguments to client data


 clnt_socket = tcp_client_socket(client_args.addr, client_args.port);

  if (clnt_socket < 0)
    handle_client_close(ERROR_CLIENT, data); // Handle error in client socket creation

  const unsigned status  = handle_auth_write(data); // Start with authentication write

  handle_client_close(status, data);

}