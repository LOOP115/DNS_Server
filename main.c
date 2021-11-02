#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>

#include "socket.h"
#include "tools.h"

#define CACHE
#define NONBLOCKING
#define PORT "8053"         // Port number
#define LOG "dns_svr.log"   // Log filename
#define BYTE_LEN 2          // Bytes of storing packet's length
#define QR 4                // Index of QR
#define RCODE 5             // Index of RCODE
#define RA 5                // Index of RA
#define QR_FIX 128          // Set QR to 1
#define RCODE_FIX 4         // Set RCODE to 4
#define RA_FIX 128          // Set RA to 1


cache_t* cache[CACHE_BUFFER];
FILE *fp;
const char* address;
const char* port;


void* handle_request(void* pnewfd);


int main(int argc, char **argv) {

    int newsockfd, sockfd_server;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size;

    // Check if command line arguments are valid
    if (argc < 3) {
        fprintf(stderr, "Invalid command line arguments\n");
        exit(EXIT_FAILURE);
    }

    // Extract upstream server address and port number
    address = argv[1];
    port = argv[2];

    // Create server socket
    sockfd_server = create_server_socket(PORT);

    // Initialize cache
    memset(cache, 0, sizeof(cache));

    // Open log file
    fp = fopen(LOG, "w");

    // Start working
    while (1) {
        // Accept a connection
        client_addr_size = sizeof(client_addr);
        newsockfd = accept(sockfd_server, (struct sockaddr*)&client_addr, &client_addr_size);
        if (newsockfd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        // Create a thread for the connection
        pthread_t t;
        int* pnewfd = malloc(sizeof(int));
        *pnewfd = newsockfd;
        pthread_create(&t, NULL, handle_request, pnewfd);
    }

    fclose(fp);
    free_cache(cache);
    close(sockfd_server);
    return 0;
}

// Handle with a dig request
void* handle_request(void* pnewfd) {
    int newsockfd = *((int*)pnewfd);
    free(pnewfd);
    // Read packet
    // Get packet's length
    unsigned char *packet_len = malloc(BYTE_LEN);
    safe_read(newsockfd, packet_len, BYTE_LEN);
    int len = get_packet_len(packet_len);

    // Get packet's message and update log
    unsigned char* packet_msg = malloc(len);
    assert(packet_msg);
    safe_read(newsockfd, packet_msg, len);
    request_log(fp, packet_msg);

    // Merge packet_len and packet_msg
    int full_len = BYTE_LEN + len;
    unsigned char *packet = malloc(full_len);
    merge_packet(packet, packet_len, packet_msg, full_len);
    // Set RA to 1
    packet[RA] = RA_FIX | packet[RA];

    // Check if type is IPV6
    int pos = get_type_index(packet_msg);
    if (is_IPV6(packet_msg, pos)) {

        // Search in the cache first
        cache_t* result = search_cache(cache, packet_msg);

        // Check if the cache works
        // No match in cache, send to upstream server
        if (result == NULL) {

            // Create client socket
            int sockfd_client = create_client_socket(address, port);

            // Send the packet to upstream server
            write(sockfd_client, packet, full_len);

            // Retrieve packet from upstream server
            unsigned char *new_packet_len = malloc(BYTE_LEN);
            safe_read(sockfd_client, new_packet_len, BYTE_LEN);
            int new_len = get_packet_len(new_packet_len);
            unsigned char* new_packet_msg = malloc(new_len);
            assert(new_packet_msg);
            safe_read(sockfd_client, new_packet_msg, new_len);
            close(sockfd_client);

            // Cache eviction and update log
            update_cache(cache, new_packet_len, new_packet_msg, fp);
            response_log(fp, new_packet_msg);

            // Merge the response packet and send it to client
            int new_full_len = BYTE_LEN + new_len;
            unsigned char *new_packet = malloc(new_full_len);
            merge_packet(new_packet, new_packet_len, new_packet_msg, new_full_len);

            // Send back to client and free memory
            new_packet[RA] = RA_FIX | new_packet[RA];
            write(newsockfd, new_packet, new_full_len);
            free(new_packet);

        } else {
            // Merge cache packet and send back to client
            int new_len = get_packet_len(result->packet_len);
            int new_full_len = BYTE_LEN + new_len;
            unsigned char *new_packet = malloc(new_full_len);
            merge_packet(new_packet, result->packet_len, result->packet_msg, new_full_len);
            new_packet[RA] = RA_FIX | new_packet[RA];
            write(newsockfd, new_packet, new_full_len);

            // Update log and free memory
            cache_log(fp, result);
            free(new_packet);
        }

    } else {
        // Modify QR, RCODE, send to client and update log
        packet[QR] = QR_FIX | packet[QR];
        packet[RCODE] = RCODE_FIX | packet[RCODE];
        write(newsockfd, packet, full_len);
        non_IPV6_log(fp);
    }

    // Free malloced space
    free(packet_len);
    free(packet_msg);
    close(newsockfd);
    return NULL;
}
