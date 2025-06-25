#ifndef TCPSERVERUTIL_H_
#define TCPSERVERUTIL_H_

#include <stdio.h>
#include <sys/socket.h>
#include "../selector.h"  // Added include for selector_key struct

typedef struct {
  char *buffer;
  size_t bufferSize;
  size_t bufferOffset;
} clientData;

// Create, bind, and listen a new TCP server socket
int setupTCPServerSocket(const char *service);

// Accept a new TCP connection on a server socket
int acceptTCPConnection(int servSock);

// Handle read events on the master socket (new connections)
void handleMasterRead(struct selector_key *key);

void handleClientRead(struct selector_key *key);

void handleTCPEchoClientClose(struct selector_key *key);

#endif