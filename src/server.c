//
// Created by nicol on 6/24/2025.
//
#include "server.h"
/**
    Handle multiple socket connections with select and fd_set on Linux
*/

#include <stdio.h>
#include <string.h>   //strlen
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>   //close
#include <arpa/inet.h>    //close
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include "selector.h"

#include "utils/tcpServerUtil.h"

#define TRUE   1
#define FALSE  0
#define PORT "8888"
#define INITIAL_MAX_CLIENTS 30
#define MAX_BUFFER_SIZE 1024

int main(int argc , char *argv[])
{
    int opt = TRUE;
    int master_socket , addrlen , new_socket ,
//    client_socket[INITIAL_MAX_CLIENTS] ,
    max_clients = INITIAL_MAX_CLIENTS , activity, i , valread , sd;
    int max_sd;
    struct sockaddr_in address;

    char buffer[MAX_BUFFER_SIZE];  //data buffer of 1K

    //set of socket descriptors
    fd_set readfds;

    //a message
    char *message = "ECHO Daemon v1.0 \r\n";

    struct selector_init conf = {
        .signal = SIGUSR1,
        .select_timeout = { .tv_sec = 5, .tv_nsec = 0 }
    };
    selector_status status = selector_init(&conf);
    if(status != SELECTOR_SUCCESS) {
        perror("Failed to initialize selector");
        exit(EXIT_FAILURE);
    }

    fd_selector selector = selector_new(INITIAL_MAX_CLIENTS);

    if (selector == NULL) {
        perror("Failed to create selector");
        exit(EXIT_FAILURE);
    }

    //initialise all client_socket[] to 0 so not checked
//    for (i = 0; i < max_clients; i++)
//    {
//        client_socket[i] = 0;
//    }
    master_socket = setupTCPServerSocket(PORT);
    if (master_socket < 0) {
        perror("Failed to setup TCP server socket");
        exit(EXIT_FAILURE);
    }

    selector_register(selector, master_socket, &(fd_handler){
        .handle_read =  handleMasterRead, // Set the function to handle incoming connections
    }, OP_READ, NULL);

    if (selector_fd_set_nio(master_socket) == -1) {
        close(master_socket);
        perror("Failed to set master socket to non-blocking mode");
        exit(EXIT_FAILURE); //TODO dudoso
    } // para que no bloquee

    while(TRUE)
    {
//        //clear the socket set
//        FD_ZERO(&readfds);
//
//        //add master socket to set
//        FD_SET(master_socket, &readfds);
//        max_sd = master_socket;

        //add child sockets to set
//        for ( i = 0 ; i < max_clients ; i++)
//        {
//            //socket descriptor
//            sd = client_socket[i];
//
//            //if valid socket descriptor then add to read list
//            if(sd > 0)
//                FD_SET( sd , &readfds);
//
//            //highest file descriptor number, need it for the select function
//            if(sd > max_sd)
//                max_sd = sd;
//        }

        //wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
        activity = selector_select( selector);

        if ((activity < 0) && (errno!=EINTR))
        {
            printf("select error");
        }

        //If something happened on the master socket , then its an incoming connection
//        if (FD_ISSET(master_socket, &readfds))
//        {
//
//
//            //inform user of socket number - used in send and receive commands
//            printf("New connection , socket fd is %d , ip is : %s , port : %d \n" , new_socket , inet_ntoa(address.sin_addr) , ntohs(address.sin_port));
//
//            //send new connection greeting message
//            if( send(new_socket, message, strlen(message), 0) != strlen(message) )
//            {
//                perror("send");
//            }
//
//            puts("Welcome message sent successfully");
//
//            //add new socket to array of sockets
//            for (i = 0; i < max_clients; i++)
//            {
//                //if position is empty
//                if( client_socket[i] == 0 )
//                {
//                    client_socket[i] = new_socket;
//                    printf("Adding to list of sockets as %d\n" , i);
//
//                    break;
//                }
//            }
//        }

//        //else its some IO operation on some other socket :)
//        for (i = 0; i < max_clients; i++)
//        {
//            sd = client_socket[i];
//
//            if (FD_ISSET( sd , &readfds))
//            {
//                //Check if it was for closing , and also read the incoming message
//                if ((valread = read( sd , buffer, 1024)) == 0)
//                {
//                    //Somebody disconnected , get his details and print
//                    getpeername(sd , (struct sockaddr*)&address , (socklen_t*)&addrlen);
//                    printf("Host disconnected , ip %s , port %d \n" , inet_ntoa(address.sin_addr) , ntohs(address.sin_port));
//
//                    //Close the socket and mark as 0 in list for reuse
//                    close( sd ); //se queda
//                    client_socket[i] = 0;//unregister
//                }
//
//                //Echo back the message that came in
//                else
//                {
//                    //set the string terminating NULL byte on the end of the data read
//                    buffer[valread] = '\0';
//                    send(sd , buffer , strlen(buffer) , 0 );
//                }
//            }
//        }
    }

    return 0;
}