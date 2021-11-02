#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "socket.h"

/* Socket programming are based on practical 9 */

/* Create and return a socket bound to the given port */
int create_server_socket(const char* port) {
    int sockfd, re ,s;
    struct addrinfo hints, *res;

    // Create address we're going to listen on (with given port number)
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_PASSIVE;     // for bind, listen, accept

    // node (NULL means any interface), service (port), hints, res
    s = getaddrinfo(NULL, port, &hints, &res);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    // Create socket
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Reuse port if possible
    re = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind address to the socket
    if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);

    // Listen on socket
    if (listen(sockfd, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

/* Create client socket */
int create_client_socket(const char* address, const char* port) {
    int sockfd, s;
    struct addrinfo hints, *servinfo, *rp;

    // Create address
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // Get addrinfo of server.
    s = getaddrinfo(address, port, &hints, &servinfo);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    // Connect to first valid result
    for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1)
            continue;
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break; // success
        close(sockfd);
    }
    if (rp == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(servinfo);

    return sockfd;
}

// Safely read packet in case of delay
void safe_read(int sockfd, unsigned char* packet, int len) {
    int i = 0;
    while (len) {
        if (read(sockfd, packet+i, 1)) {
            i++;
            len--;
        }
    }
}
