//
// Created by nicol on 6/24/2025.
//
#include "server.h"
/**
    Handle multiple socket connections with select and fd_set on Linux
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>   //close
#include <sys/types.h>

#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include "selector.h"
#include <signal.h>

#include "tcpServerUtil.h"

#define TRUE   1
#define FALSE  0
#define PORT "1080"
#define INITIAL_MAX_CLIENTS 30
#define MAX_BUFFER_SIZE 1024

int main()
{
    // int max_clients = INITIAL_MAX_CLIENTS;

    const struct selector_init conf = {
        .signal = SIGUSR1,
        .select_timeout = { .tv_sec = 5, .tv_nsec = 0 }
    };
    const selector_status status = selector_init(&conf);
    if(status != SELECTOR_SUCCESS) {
        perror("Failed to initialize selector");
        exit(EXIT_FAILURE);
    }

    fd_selector selector = selector_new(INITIAL_MAX_CLIENTS);

    if (selector == NULL) {
        perror("Failed to create selector");
        exit(EXIT_FAILURE);
    }

    const int master_socket = setupTCPServerSocket(PORT);
    if (master_socket < 0) {
        perror("Failed to setup TCP server socket");
        exit(EXIT_FAILURE);
    }

    selector_register(selector, master_socket, &(fd_handler){
        .handle_read =  handleMasterRead, // funcion para crear sockets activos
    }, OP_READ, NULL);

    if (selector_fd_set_nio(master_socket) == -1) {
        close(master_socket);
        perror("Failed to set master socket to non-blocking mode");
        exit(EXIT_FAILURE);
    } // para que no bloquee

    while(TRUE)
    {
        //wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
        const int activity = selector_select(selector);

        if (activity < 0 && errno!=EINTR)
        {
            printf("select error");
        }
    }

    return 0;
}