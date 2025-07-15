#ifndef TCPSERVERUTIL_H_
#define TCPSERVERUTIL_H_

#include <sys/socket.h>
#include <netinet/in.h>    // For struct in6_addr and struct sockaddr_in
#include "../selector.h"  // Added include for selector_key struct
#include "../stm.h"
#include "../buffer.h"
#include <netdb.h>
#include "../metrics/metrics.h"

#define SOCKS_VERSION 5 // Version for SOCKS protocol
#define CONNECT 1
#define RSV 0
#define SUBNEGOTIATION_VERSION 0x01 // Subnegotiation method for password authentication
#define MAX_ADDR_BUFFER 128

#define REQUEST_HEADER 4 // Size of the request header (version, command, reserved, address type)
#define IPV4_ADDR_SIZE 4 // Size of IPv4 address in bytes
#define IPV6_ADDR_SIZE 16 // Size of IPv6 address in bytes

#define PORT_STR_SIZE 6 // Size of port string (max 5 digits + null terminator)
#define PORT_SIZE 2 // Size of port in bytes (16 bits)

#define MAX_DOMAIN_LENGTH 255 // Maximum length of a domain name

enum socks5_auth_methods {
    AUTH_METHOD_NOAUTH = 0x00, // No authentication required
    AUTH_METHOD_PASSWORD = 0x02, // Username/password authentication
    NO_ACCEPTABLE_METHODS = 0xFF // No acceptable methods
};

enum socks5_auth_status {
    AUTH_SUCCESS = 0x00, // Authentication successful
    AUTH_FAILURE = 0x01, // Authentication failed
};

enum socks5_respose_size {
    SOCKS5_IPV4_REQUEST = 10, // Size of the SOCKS5 response header
    SOCKS5_IPV6_REQUEST = 22, // Size of the SOCKS5 response header for IPv6
    SOCKS5_MAX_REQUEST_RESPONSE = 22 // Maximum size of the SOCKS5 response
};

// SOCKS5 response status codes for the request stage (RFC 1928)




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
  FAILURE_RESPONSE,
  AWAITING_RESOLUTION,
  DOMAIN_RESOLVING,
};

enum relay_states {
  RELAY_CONNECTING,
  RELAY_REMOTE,
  RELAY_DONE,
  RELAY_ERROR,
};

enum ADDRESS_TYPE {
  IPV4 = 0x01,        // IPv4 address
  DOMAINNAME = 0x03,  // Domain name
  IPV6 = 0x04         // IPv6 address
};

typedef struct client_data client_data;

struct originInfo {
  uint8_t address_type; // Address type (IPv4, IPv6, or domain name)
  union {
    uint32_t ipv4; // IPv4 address in network byte order
    struct in6_addr ipv6; // IPv6 address
  } address;
  uint16_t port; // Origin port
};

struct destination_info {
    uint8_t address_type; // Address type (IPv4, IPv6, or domain name)
    union {
        uint32_t ipv4; // IPv4 address in network byte order
        struct in6_addr ipv6; // IPv6 address
        char domain_name[256]; // Domain name
    } address;
    uint16_t port; // Destination port
};

struct auth_info {
    char username[256];
    char password[256];
};

struct dns_res {
    int gai_error;
    struct addrinfo *addrinfo; // Pointer to the address info for the DNS resolution
};

struct dns_req{
    client_data * client_data; // Pointer to the client data structure
    struct gaicb *request;
    struct gaicb **list; // Pointer to the list of DNS requests
    fd_selector fd_selector;
    struct addrinfo *hints; // Pointer to the address info for the DNS request
    int fd; // File descriptor for the DNS request
    char port[6]; // Port string for the DNS request
};

 struct client_data {
     buffer * client_buffer;
     buffer *remote_buffer; // Buffer for reading/writing data to the remote socket

     int remote_socket; // Socket for the remote connection
     int client_socket; // Socket for the client connection

     struct state_machine *stm; // Pointer to the state machine
     struct state_machine *remote_stm; // Pointer to the state machine

     uint8_t auth_method;
     struct auth_info auth_info; // Authentication information
     uint8_t is_anonymous; // Flag to indicate if the client is anonymous

     struct destination_info destination; // Destination information
     struct originInfo origin; // Origin information

     int response_status; // Status of the response to the client
     user_connection current_user_conn;

     struct dns_req *dns_request; // Pointer to the DNS request structure
     int address_resolved; // Flag to indicate if the callback is ready

     struct addrinfo *remote_addrinfo; // Address info for the remote connection in case we need to try another address
     struct addrinfo *pointer_to_free; // Pointer to the address info to free later

     struct timespec last_activity;
 };

// Create, bind, and listen a new TCP server socket
int setup_tcp_server_socket(const char *addr, const int port);

int setup_tcp_remote_socket(const struct destination_info *destination, struct selector_key *key);

// Accept a new TCP connection on a server socket
int accept_tcp_connection(int serv_sock);

// Handle read events on the master socket (new connections)
void handle_master_read( struct selector_key *key);

void handle_master_close(struct selector_key *key);

void handleClientRead(struct selector_key *key);

void handleTCPEchoclient_close(struct selector_key *key);
void set_response_status(client_data *data, int error);
int remote_socket_init(const int remote_socket, const struct selector_key *key, int initial_state, int interest);

void socks5_close(struct selector_key *key);
void socks5_read(struct selector_key *key);
void socks5_write(struct selector_key *key);
void socks5_block(struct selector_key *key, void *data);
void socks5_timeout(struct selector_key *key);

#endif
