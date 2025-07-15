#ifndef UTIL_H_
#define UTIL_H_

#include <sys/socket.h>
#include <netdb.h>


int print_socket_address(const struct sockaddr *address, char * addr_buffer);

const char * printFamily(struct addrinfo *aip);
const char * printType(struct addrinfo *aip);
const char * printProtocol(struct addrinfo *aip);
void printFlags(struct addrinfo *aip);
char * print_address_port( const struct addrinfo *aip, char addr[]);

// Determina si dos sockets son iguales (misma direccion y puerto)
int sockAddrsEqual(const struct sockaddr *addr1, const struct sockaddr *addr2);

#endif