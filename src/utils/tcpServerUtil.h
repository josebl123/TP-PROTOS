#ifndef TCPSERVERUTIL_H_
#define TCPSERVERUTIL_H_

#include <stdio.h>
#include <sys/socket.h>
#include "../selector.h"  // Added include for selector_key struct


// Create, bind, and listen a new TCP server socket
int setupTCPServerSocket(const char *service);

// Accept a new TCP connection on a server socket
int acceptTCPConnection(int servSock);

// Handle new TCP client
int handleTCPEchoClient(int clntSocket);  // Changed return type to int to match implementation

// Handle read events on the master socket (new connections)
void handleMasterSocketRead(struct selector_key *key);

void handle_client_read(struct selector_key *key);

void handleTCPEchoClientClose(struct selector_key *key);

#endif