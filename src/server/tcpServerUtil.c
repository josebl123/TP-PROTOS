#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include  <signal.h>
#include "../utils/logger.h"
#include "../utils/util.h"
#include "tcpServerUtil.h"

#include "args.h"
#include "socksAuth.h"
#include "socksRelay.h"
#include "server/server.h"
#include "socksRequest.h"

#include "../selector.h"
#include "../buffer.h"
#include "../metrics/metrics.h"
#include "../utils/user_metrics_table.h"


#define MAXPENDING 20 // Maximum outstanding connection requests
#define TIMEOUT_INCOMPLETE_MSG_SEC (60 * 2)

static char addr_buffer[MAX_ADDR_BUFFER];

void socks5_relay_read(struct selector_key *key);
void socks5_relay_write(struct selector_key *key);

/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
void handle_tcp_close(  struct selector_key *key) {
    client_data *data =  key->data;

    gai_cancel(data->dns_request->request); // Cancelar la solicitud de DNS si está pendiente

    selector_unregister_fd( key->s,data->remote_socket); // Desregistrar el socket remoto

    free(data->client_buffer->data);
    free(data->client_buffer);
    if (data->remote_buffer) {
        free(data->remote_buffer->data);
        free(data->remote_buffer);
    }
    if (data->pointer_to_free) {
        freeaddrinfo(data->pointer_to_free); // Liberar la estructura de direcciones remotas
    }
    user_metrics * user_metric = get_or_create_user_metrics(data->auth_info.username);

    char time_str[64];
    struct tm tm_info;
    localtime_r(&data->current_user_conn.access_time, &tm_info);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);
    data->current_user_conn.status = data->response_status;
    metrics_connection_closed();

    data->current_user_conn.port_origin = data->origin.port;
    fill_ip_address_from_origin(&data->current_user_conn.ip_origin, &data->origin);

    if (!data->is_anonymous ) {
        user_metrics_add_connection(user_metric, &data->current_user_conn);
    }
    else if (socks_args->server_accepts_no_auth) {
        user_metrics * user_metrics = get_or_create_user_metrics(ANONYMOUS_USER);
        user_metrics_add_connection(user_metrics, &data->current_user_conn);
    }

    free(data->stm);
    free(data->remote_stm);
    free(data);

    close(key->fd);
}
void handle_remote_close( struct selector_key *key) {
    close(key->fd);
}
void client_close(const unsigned state, struct selector_key *key) {

    selector_unregister_fd(key->s, key->fd); // Desregistrar el socket del selector
}


void remote_close(const unsigned state, struct selector_key *key) {
    client_data *data =  key->data;
    selector_unregister_fd(key->s, data->client_socket);
}

 static const struct state_definition states[] = {
    [HELLO_READ] =    { .state = HELLO_READ, .on_read_ready = handle_hello_read },
    [HELLO_WRITE] =   { .state = HELLO_WRITE, .on_write_ready = handle_hello_write },
    [AUTH_READ] =     { .state = AUTH_READ, .on_read_ready = handle_auth_read },
    [AUTH_WRITE] =    { .state = AUTH_WRITE, .on_write_ready = handle_auth_write },
    [REQUEST_READ] =  { .state = REQUEST_READ, .on_read_ready = handle_request_read },
    [REQUEST_WRITE] = { .state = REQUEST_WRITE, .on_write_ready = handle_request_write },
    [DOMAIN_RESOLVING] = { .state = DOMAIN_RESOLVING, .on_block_ready = handle_domain_resolve}, // Resolving domain name
    [AWAITING_RESOLUTION] = { .state = AWAITING_RESOLUTION, .on_block_ready = handle_callback }, // Waiting for DNS resolution
    [DONE] =          { .state = DONE, .on_arrival = client_close },
    [ERROR_CLIENT] =  { .state = ERROR_CLIENT,.on_arrival = client_close},
    [FAILURE_RESPONSE] = { .state = FAILURE_RESPONSE, .on_write_ready = send_failure_response_client }, // Write failure response to client
    [RELAY_CLIENT] = { .state = RELAY_CLIENT, .on_read_ready = handle_relay_client_read,.on_write_ready = handle_relay_client_write  },
};

static const struct state_definition relay_states[] = {
    [RELAY_CONNECTING] = { .state = RELAY_CONNECTING, .on_write_ready =  connect_write}, // This state handles the connection to the remote server
    [RELAY_REMOTE] = { .state = RELAY_REMOTE, .on_read_ready = handle_relay_remote_read, .on_write_ready = handle_relay_remote_write },
    [FAILURE_RESPONSE] = { .state = FAILURE_RESPONSE, .on_write_ready = send_failure_response_remote }, // Write failure response to remote
    [RELAY_DONE] = { .state = RELAY_DONE, .on_arrival = remote_close },
    [RELAY_ERROR] = { .state = RELAY_ERROR, .on_arrival = remote_close },
};

static const fd_handler client_handler = {
    .handle_read = socks5_read, // Initial read handler
    .handle_write = socks5_write, // Initial write handler
    .handle_block = socks5_block, // Block handler for DNS resolution
    .handle_close =  handle_tcp_close,
    .handle_timeout = socks5_timeout,
};
static const fd_handler relay_handler = {
    .handle_read = socks5_relay_read, // Relay read handler
    .handle_write = socks5_relay_write, // Relay write handler
    .handle_block = NULL, // Not used in this case
    .handle_close = handle_remote_close, // Relay close handler
    .handle_timeout = NULL // No timeout handling for relay
};


int setup_tcp_server_socket(const char *ip, const int port) {
    // Construct the server address structure
    struct addrinfo addr_criteria = {0};                   // Criteria for address match
    addr_criteria.ai_family = AF_UNSPEC;             // Any address family
    addr_criteria.ai_socktype = SOCK_STREAM;         // Only stream sockets
    addr_criteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol
    // Convertir el puerto a string
    char port_str[6];   // Máx: 65535 + null
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo *serv_addr; 			// List of server addresses
    const int rtn_val = getaddrinfo(ip, port_str, &addr_criteria, &serv_addr);
    if (rtn_val != 0) {
        log(FATAL, "getaddrinfo() failed %s", gai_strerror(rtn_val));
        return -1;
    }

    int serv_sock = -1;
    // Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio, sin especificar una IP en particular
    // Iteramos y hacemos el bind por alguna de ellas, la primera que funcione, ya sea la general para IPv4 (0.0.0.0) o IPv6 (::/0) .
    // Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
    for (const struct addrinfo *addr = serv_addr; addr != NULL && serv_sock == -1; addr = addr->ai_next) {
        errno = 0;
        // Create a TCP socket
        serv_sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (serv_sock < 0) {
            log(DEBUG, "Cant't create socket on %s : %s ", print_address_port(addr, addr_buffer), strerror(errno));
            continue;       // Socket creation failed; try next address
        }

       setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)); // Allow reuse of address

        // Bind to ALL the address and set socket to listen
        if (bind(serv_sock, addr->ai_addr, addr->ai_addrlen) == 0 && listen(serv_sock, MAXPENDING) == 0) {
            // Print local address of socket
            struct sockaddr_storage local_addr;
            socklen_t addr_size = sizeof(local_addr);
            if (getsockname(serv_sock, (struct sockaddr *) &local_addr, &addr_size) >= 0) {
                print_socket_address((struct sockaddr *) &local_addr, addr_buffer);
                log(INFO, "Binding to %s", addr_buffer);
            }
        } else {
            log(DEBUG, "Cant't bind %s", strerror(errno));
            close(serv_sock);  // Close and try with the next one
            serv_sock = -1;
        }
    }

    freeaddrinfo(serv_addr);

    return serv_sock;
}
struct state_machine * create_remote_state_machine(int initial_state) {
    struct state_machine *stm = malloc(sizeof(struct state_machine));
    if (stm == NULL) {
        log(ERROR, "Failed to allocate memory for remote state machine");
        return NULL;
    }
    stm->initial = initial_state; // Initial state for remote relay
    stm->states = relay_states; // Use the relay states defined above
    stm->max_state = RELAY_ERROR; // Total number of states in the relay machine
    stm_init(stm);
    return stm;
}
int remote_socket_init(const int remote_socket, const struct selector_key *key, int initial_state, int intertest) {
    client_data *data = key->data;

    buffer *remote_buffer = malloc(sizeof(buffer)); // Create a buffer for the remote socket
    if (remote_buffer == NULL) {
        log(ERROR, "Failed to allocate memory for remote buffer");
        data->response_status = SOCKS5_GENERAL_FAILURE;
        return -1;
    }
    remote_buffer->data = malloc(buffer_size); // Allocate memory for the buffer data
    if (remote_buffer->data == NULL) {
        log(ERROR, "Failed to allocate memory for remote buffer data");
        data->response_status = SOCKS5_GENERAL_FAILURE;
        return -1;
    }
    buffer_init(remote_buffer, buffer_size, remote_buffer->data); // Initialize the buffer with a size

    data->remote_buffer = remote_buffer; // Set the buffer for the remote socket
    data->remote_stm = create_remote_state_machine(initial_state); // Create the state machine for the remote socket
    data->remote_socket = remote_socket; // Store the remote socket in client data
    data->client_socket = key->fd; // Store the client socket in client data

    // Register the remote socket with the selector
    if (selector_register(key->s, remote_socket, &relay_handler, intertest, data) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to register remote socket %d with selector", remote_socket);
        data->response_status = SOCKS5_GENERAL_FAILURE;
        return -1;
    }

    return 0;
}


void set_response_status(client_data *data, int error) {
    switch (error) {
        case EACCES:
            data->response_status = SOCKS5_CONNECTION_NOT_ALLOWED;
            break;
        case ENETUNREACH:
            data->response_status = SOCKS5_NETWORK_UNREACHABLE;
            break;
        case EHOSTDOWN:
        case EHOSTUNREACH:
            data->response_status = SOCKS5_HOST_UNREACHABLE;
            break;
        case ECONNREFUSED:
            data->response_status = SOCKS5_CONNECTION_REFUSED;
            break;
        case ETIMEDOUT:
            data->response_status = SOCKS5_TTL_EXPIRED;
            break;
        default:
            data->response_status = SOCKS5_GENERAL_FAILURE; // Default error code
            break;
    }
}

void get_addr_info_callback(union sigval sigval) {
    struct dns_req *req = sigval.sival_ptr; // Get the request from the signal value

    struct dns_res *dns_response = malloc(sizeof(struct dns_res)); // Allocate memory for the DNS response
    if (dns_response == NULL) {
        log(ERROR, "Failed to allocate memory for DNS response");
        metrics_add_host_unreachable_error();
    } else {
        dns_response->gai_error = gai_error(req->request); // Get the error code from the request
        dns_response->addrinfo = req->request->ar_result; // Get the address info from the request
    }

    if (selector_notify_block(req->fd_selector, req->fd, dns_response) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to notify selector for fd %d", req->fd);
        free(req->request);
        free(req->hints);
        free(req->list);
        free(req);
    }
}


int setup_tcp_remote_socket(const struct destination_info *destination,  struct selector_key * key) {
    client_data *data = key->data; // Get the client data from the key
    int remote_sock = -1;
    // Connect to the remote address
    struct sockaddr_storage remote_addr = {0};
    socklen_t addr_len = 0;

    if (destination->address_type == IPV4) {
         remote_sock = socket( AF_INET, SOCK_STREAM, 0);
        if (remote_sock < 0) {
            log(ERROR, "socket() failed: %s", strerror(errno));
            data->response_status = SOCKS5_GENERAL_FAILURE;
            metrics_add_server_error();
            return -1;
        }
        data->remote_socket = remote_sock; // Store the remote socket in client data

        // Set the socket to non-blocking mode
        if (selector_fd_set_nio(remote_sock) < 0) {
            log(ERROR, "Failed to set remote socket to non-blocking mode: %s", strerror(errno));
            data->response_status = SOCKS5_GENERAL_FAILURE;
            metrics_add_server_error();
            return -1;
        }
        struct sockaddr_in *addr = (struct sockaddr_in *) &remote_addr;
        addr->sin_family = AF_INET;
        addr->sin_port = htons(destination->port);
        addr->sin_addr.s_addr = htonl(destination->address.ipv4);
        addr_len = sizeof(struct sockaddr_in);
        metrics_add_ipv4_connection();

    } else if (destination->address_type == IPV6) {
        remote_sock = socket( AF_INET6, SOCK_STREAM, 0);
        if (remote_sock < 0) {
            log(ERROR, "socket() failed: %s", strerror(errno));
            data->response_status = SOCKS5_GENERAL_FAILURE;
            metrics_add_server_error();
            return -1;
        }

        // Set the socket to non-blocking mode
        if (selector_fd_set_nio(remote_sock) < 0) {
            log(ERROR, "Failed to set remote socket to non-blocking mode: %s", strerror(errno));
            data->response_status = SOCKS5_GENERAL_FAILURE;
            metrics_add_server_error();
            return -1;
        }
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &remote_addr;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(destination->port);
        memcpy(&addr->sin6_addr, &destination->address.ipv6, sizeof(struct in6_addr));
        addr_len = sizeof(struct sockaddr_in6);
        metrics_add_ipv6_connection();
    } else if (destination->address_type == DOMAINNAME) {
        struct dns_req *dns_request = data->dns_request; // Get the DNS request structure from client data
        snprintf(dns_request->port, sizeof(dns_request->port), "%d", destination->port);

        struct gaicb *request = calloc(1, sizeof(struct gaicb)); // Allocate memory for the request array
        request->ar_name = destination->address.domain_name; // Set the domain name for the DNS request
        request->ar_service = dns_request->port;
        request->ar_result = NULL; // Initialize result to NULL

        struct addrinfo *hints = calloc(1, sizeof(struct addrinfo)); // Allocate memory for the hints structure

        hints->ai_protocol = IPPROTO_TCP; // Set the protocol for the DNS request
        hints->ai_family = AF_UNSPEC; // Allow both IPv4 and IPv6
        hints->ai_socktype = SOCK_STREAM; // TCP socket type


        request->ar_request = hints; // Set the request pointer


        dns_request->client_data = data; // Set the client data for the DNS request
        dns_request->fd_selector = key->s; // Set the selector for the DNS request
        dns_request->fd = key->fd; // Set the file descriptor for the DNS request
        dns_request->request = request;
        dns_request->hints = hints;

        struct gaicb **list = calloc(2, sizeof(struct gaicb *)); // Allocate memory for the request list
        list[0] = request; // Set the first request in the list
        list[1] = NULL; // Null-terminate the list

        dns_request->list = list; // Set the request list in the DNS request structure

        // Set up signal event for the callback
        struct sigevent sigevent = {0}; // Initialize the sigevent structure
        sigevent.sigev_notify = SIGEV_THREAD;  // Use a thread to handle the callback
        sigevent.sigev_notify_function = get_addr_info_callback;  // Set the callback function
        sigevent.sigev_value.sival_ptr = dns_request;  // Pass the DNS request to the callback

        // Set the interest to OP_NOOP to wait for the DNS resolution callbackx
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for DNS request key %d", key->fd);
            data->response_status = SOCKS5_GENERAL_FAILURE;
            metrics_add_server_error();
            return -1;
        }
        metrics_add_dns_resolution();

        // Call getaddrinfo_a asynchronously
        int gaiResult = getaddrinfo_a(GAI_NOWAIT, list, 1, &sigevent);
        if (gaiResult != 0) {
            log(ERROR, "getaddrinfo_a() failed for domain %s: %s",
                destination->address.domain_name, gai_strerror(gaiResult));
            data->response_status = SOCKS5_HOST_UNREACHABLE;
            metrics_add_host_unreachable_error();
            return -1;
        }


        data->address_resolved = 0; // Indicate that the address is not resolved yet
        return 0; // Return 0 to indicate that the DNS request is in progress

    } else {
        log(ERROR, "Unsupported address type: %d", destination->address_type);
        metrics_add_unsupported_input();
        return -1;
    }

    int connected = connect(remote_sock, (struct sockaddr *) &remote_addr, addr_len);
    if (connected < 0 && errno != EINPROGRESS) {
        log(ERROR, "connect() failed: %s", strerror(errno));
        int error = errno;
        set_response_status(data, error); // Set the appropriate response status based on the error
        return -1;
    }

    if (!connected) {
        log(INFO, "CONNECTED IMMEDIATELY");
        if (remote_socket_init(remote_sock, key, RELAY_REMOTE, OP_NOOP) < 0 ) {
            log(ERROR, "Failed to initialize remote socket");
            return -1; // Initialize the remote socket
        }
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
            metrics_add_server_error();
            return -1;
        }
        data->address_resolved = 1; // Indicate that the address is resolved (success)
    } else {
        if (remote_socket_init(remote_sock, key, RELAY_CONNECTING, OP_WRITE) < 0 ) {
            log(ERROR, "Failed to initialize remote socket");
            return -1; // Initialize the remote socket
        }
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            log(ERROR, "Failed to set interest for client socket %d", key->fd);
            data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
            metrics_add_server_error();
            return -1;
        }
    }
    // Print remote address of socket
    print_socket_address((struct sockaddr *) &remote_addr, addr_buffer);
    return remote_sock;
}

int accept_tcp_connection(int serv_sock) {
    struct sockaddr_storage clnt_addr; // Client address
    // Set length of client address structure (in-out parameter)
    socklen_t clnt_addr_len = sizeof(clnt_addr);

    // Wait for a client to connect
    const int clnt_sock = accept(serv_sock, (struct sockaddr *) &clnt_addr, &clnt_addr_len);
    if (clnt_sock < 0) {
        log(ERROR, "accept() failed");
        return -1;
    }
    metrics_new_connection(); // Registrar nueva conexión anónima

    // clnt_sock is connected to a client!
    print_socket_address((struct sockaddr *) &clnt_addr, addr_buffer);

    return clnt_sock;
}

unsigned handle_callback(struct selector_key *key, void *data) {
    struct dns_res *res = data; // Get the DNS request from the data pointer
    client_data *client_data = key->data; // Get the client data from the request

    if (res == NULL) {
        log(ERROR, "DNS resolution callback received NULL response");
        client_data->response_status = SOCKS5_GENERAL_FAILURE; // Set general failure status
        return send_failure_response_client(key); // Exit if the response is NULL
    } else {
        free(client_data->dns_request->request); // Free the request structure
        free(client_data->dns_request->hints); // Free the hints structure
        free(client_data->dns_request->list); // Free the request list
        free(client_data->dns_request); // Free the DNS request structure
    }

    if (res->gai_error != 0) {
        log(ERROR, "getaddrinfo() failed: %s", gai_strerror(res->gai_error));
        client_data->response_status = SOCKS5_HOST_UNREACHABLE; // Set the response status to host unreachable
        metrics_add_dns_resolution_error();
        client_data->address_resolved = 1; // Mark the address as resolved (failed)
        free(res);
        return send_failure_response_client(key); // Exit if getaddrinfo failed
    }

    client_data->address_resolved = 0; // Mark the address as not resolved (success)
    client_data->remote_addrinfo = res->addrinfo; // Store the result in client data
    client_data->pointer_to_free = res->addrinfo; // Store the pointer to free later

    free(res); // Free the DNS response data

    return handle_domain_resolve(key, NULL); // Call the domain resolve handler to continue processing
}


int initialize_client_data(client_data *data) {
    struct state_machine *stm = malloc(sizeof(struct state_machine));
    if (stm == NULL) {
        perror("Failed to allocate memory for state machine");
        exit(EXIT_FAILURE);
    }
    stm->initial = HELLO_READ;
    stm->states = states;
    stm->max_state = DOMAIN_RESOLVING; // Total number of states
    stm_init(stm);
	buffer *buf = malloc(sizeof(buffer));
    if (buf == NULL) {
        perror("Failed to allocate memory for buffer");
        free(stm);
        free(data);
        return -1;
    }
    buf->data = malloc(buffer_size * sizeof(char)); // Allocate buffer data
    if (buf->data == NULL) {
        perror("Failed to allocate memory for buffer data");
        free(buf);
        free(stm);
        free(data);

        return -1;
    }
    buffer_init(buf, buffer_size, buf->data); // Initialize the buffer

    data->client_buffer = buf;
    data->remote_buffer = NULL; // Initialize remote buffer to NULL

    struct dns_req *dns_request = malloc(sizeof(struct dns_req));
    if (dns_request == NULL) {
        perror("Failed to allocate memory for DNS request");
        free(buf->data);
        free(buf);
        free(stm);
        free(data);
        return -1;
    }
    memset(dns_request, 0, sizeof(struct dns_req)); // Initialize DNS request structure
    data->dns_request = dns_request; // Initialize the DNS request structure
    data->pointer_to_free = NULL; // Initialize remote address info to NULL

    data->address_resolved = 0; // Initialize address resolved flag to false

    data->auth_method = NO_ACCEPTABLE_METHODS; // Error auth method
    data->stm = stm; // Assign the state machine to client data
    data->is_anonymous = 1; // Initialize anonymous flag to true
    memset(&data->current_user_conn, 0, sizeof(data->current_user_conn)); // Initialize current user connection data
    user_connection_init(&data->current_user_conn);
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);
    return 0;
}
void handle_master_close(struct selector_key *key) {
    close(key->fd); // Close the master socket
}

void handle_master_read(struct selector_key *key) {
    struct sockaddr_storage address;
    socklen_t addr_len = sizeof(address);

    // aceptamos
    const int new_socket = accept_tcp_connection(key->fd);
    if (new_socket < 0) {
        log(ERROR, "Failed to accept new connection");
        return;
    }

    // bloqueo = no
    if (selector_fd_set_nio(new_socket) == -1) {
        log(ERROR, "Failed to set non-blocking mode for new socket %d", new_socket);
        close(new_socket);
        return;
    }

    getpeername(new_socket, (struct sockaddr*)&address, &addr_len);
    if (((struct sockaddr *)&address)->sa_family != AF_INET &&
      ((struct sockaddr *)&address)->sa_family != AF_INET6) {
        log(ERROR, "Unsupported address family: %d", ((struct sockaddr *)&address)->sa_family);
        close(new_socket);
        return;
      }

    // Prepare client data structure
    client_data *data = calloc(1, sizeof(client_data));
     if (data == NULL) {
        log(ERROR, "Failed to allocate memory for client data");
        return ;
    }

    if (initialize_client_data(data) < 0) {
        close(new_socket);
        return; // Error initializing client data
    }

    // Set origin info
    if (((struct sockaddr *)&address)->sa_family) {
        const struct sockaddr_in * addr4 = (struct sockaddr_in *)&address;
        data->origin.address_type = IPV4;
        data->origin.address.ipv4 = addr4->sin_addr.s_addr;
        data->origin.port = ntohs(addr4->sin_port);
    } else if (((struct sockaddr *)&address)->sa_family) {
        data->origin.address_type = IPV6;
        const struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&address;
        memcpy(&data->origin.address.ipv6, &addr6->sin6_addr, sizeof(struct in6_addr));
        data->origin.port = ntohs(addr6->sin6_port);
    }


    // Registrar con interés inicial
    if (SELECTOR_SUCCESS != selector_register(key->s, new_socket, &client_handler, OP_READ, data)) {
        log(ERROR, "Failed to register client socket %d with selector in master read", new_socket);
        free(data->client_buffer);
        free(data);
        close(new_socket);
    }
}

void socks5_relay_read(struct selector_key *key) {
    const client_data *data = key->data;
    if (data != NULL && data->remote_stm != NULL) {
        stm_handler_read(data->remote_stm, key); // Read data from the remote socket
    }
}

void socks5_relay_write(struct selector_key *key) {
    const client_data *data = key->data;
    if (data != NULL && data->remote_stm != NULL) {
        stm_handler_write(data->remote_stm, key); // Write data to the remote socket
    }
}

void socks5_close(struct selector_key *key) {
    const client_data *data = key->data;
    if (data != NULL) {
        stm_handler_close(data->stm, key);
    }
}

void socks5_read(struct selector_key *key) {
    client_data *data = key->data;
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);
    stm_handler_read(data->stm, key); //usar enum para detectar errores
}

void socks5_write(struct selector_key *key) {
    client_data *data = key->data;
    clock_gettime(CLOCK_MONOTONIC, &data->last_activity);
    stm_handler_write(data->stm, key);
}

void socks5_block(struct selector_key *key, void *data) {
    client_data *client_data = key->data;
    clock_gettime(CLOCK_MONOTONIC, &client_data->last_activity);
    stm_handler_block(client_data->stm, key, data);
}

void socks5_timeout(struct selector_key *key) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    client_data *client_data =key->data;
    const unsigned current_state = stm_state(client_data->stm);
    fd_interest interest;
    if (selector_get_interest(key->s,key->fd, &interest) != SELECTOR_SUCCESS) {
        log(ERROR, "Failed to get interest for key %d", key->fd);
        return;
    }
    if ( current_state == DOMAIN_RESOLVING || interest == OP_NOOP) {
        return;
    }

    if (difftime(now.tv_sec, client_data->last_activity.tv_sec) > TIMEOUT_INCOMPLETE_MSG_SEC) {
        selector_unregister_fd(key->s, key->fd);
    }
}
