#ifndef TCPSERVERUTIL_H_
#define TCPSERVERUTIL_H_

#include <sys/socket.h>
#include <netinet/in.h>    // For struct in6_addr and struct sockaddr_in
#include "../selector.h"  // Added include for selector_key struct
#include "../stm.h"
#include "../buffer.h"

#define SOCKS_VERSION 5 // Version for SOCKS protocol
#define AUTH_METHOD_PASSWORD 2 // Authentication method for password
#define SUBNEGOTIATION_VERSION 0x01 // Subnegotiation method for password authentication
#define NO_ACCEPTABLE_METHODS 0xFF // No acceptable methods

enum socks5_states {
  HELLO_READ,
  HELLO_WRITE,
  AUTH_READ,
  AUTH_WRITE,
  REQUEST_READ,
  REQUEST_WRITE,
  DONE,
  ERROR_CLIENT,
  RELAY_CLIENT,
};

enum relay_states {
  RELAY_REMOTE,
  RELAY_DONE,
  RELAY_ERROR,
};

enum ADDRESS_TYPE {
  IPV4 = 0x01,        // IPv4 address
  DOMAINNAME = 0x03,  // Domain name
  IPV6 = 0x04         // IPv6 address
};


typedef struct {
  buffer * clientBuffer;
  size_t bufferSize;
  size_t bufferOffset;
  struct state_machine *stm; // Pointer to the state machine
  uint8_t authMethod;
  struct auth_info {
    char username[256];
    char password[256];
  } authInfo; // Authentication information

  struct destination_info {
    uint8_t addressType; // Address type (IPv4, IPv6, or domain name)
    union {
        uint32_t ipv4; // IPv4 address in network byte order
        struct in6_addr ipv6; // IPv6 address
        char domainName[256]; // Domain name
    } address;
    uint16_t port; // Destination port
  } destination; // Destination information

  int remoteSocket; // Socket for the remote connection
  buffer *remoteBuffer; // Buffer for reading/writing data to the remote socket
} clientData;

typedef struct {
    int client_fd; // File descriptor for the remote socket
    struct sockaddr_storage remoteAddr; // Remote address information
    clientData *client; // Pointer to the client data structure
    struct state_machine *stm; // Pointer to the state machine
    buffer *buffer; // Buffer for reading/writing data
} remoteData;

// Create, bind, and listen a new TCP server socket
int setupTCPServerSocket(const char *service);

// Accept a new TCP connection on a server socket
int acceptTCPConnection(int servSock);

// Handle read events on the master socket (new connections)
void handleMasterRead( struct selector_key *key);

void handleClientRead(struct selector_key *key);

void handleTCPEchoClientClose(struct selector_key *key);



// Handle reading the request from the client
unsigned handleRequestRead(struct selector_key *key);
// Handle writing to the client socket
unsigned handleRequestWrite(struct selector_key *key);

 void socks5_close(struct selector_key *key);
void socks5_read(struct selector_key *key);
void socks5_write(struct selector_key *key);
void socks5_block(struct selector_key *key);

#endif