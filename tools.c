#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "tools.h"

// Calculate packet length based on the first two bytes
int get_packet_len(unsigned char* packet_len) {
    int len = packet_len[0] << 8;
    len += packet_len[1];
    return len;
}

// Write timestamp to log
void write_timestamp(FILE* log) {
    time_t raw;
    char res[100];
    struct tm* time_info;

    time(&raw);
    time_info = localtime(&raw);
    strftime(res, 100, "%FT%T%z", time_info);
    fprintf(log, "%s ", res);
}

// Get the index which indicates the type
int get_type_index(unsigned char* packet_msg) {
    int len = packet_msg[INIT];
    int pos = INIT;
    while (len) {
        pos += len + 1;
        len = packet_msg[pos];
    }
    return pos + 1;
}

// Count how many parts are there in the domain name and check if the type is AAAA
int count_parts(unsigned char* packet_msg) {
    // Count the number of parts
    int len = packet_msg[INIT];
    int pos = INIT;
    int count = 0;
    while (len) {
        pos += len + 1;
        count++;
        len = packet_msg[pos];
    }
    return count;
}

// Check if the type is AAAA
int is_IPV6(unsigned char* packet_msg, int pos) {
    return packet_msg[pos] == 0 && packet_msg[pos + 1] == 28;
}

// Retrieve domain name from packet
void get_domain(unsigned char* domain, unsigned char* packet_msg, int num) {
    int pos = 0;
    int start = INIT;
    while (num) {
        int len = packet_msg[start];
        for (int i=0; i<len; i++) {
            domain[pos] = packet_msg[start+i+1];
            pos++;
        }
        // Check if it is the last part which doesn't need '.'
        if (num != 1) {
            domain[pos] = '.';
            pos++;
        }
        num--;
        start += len + 1;
    }
    domain[pos] = '\0';
}

// Update log when there is a request
void request_log(FILE* log, unsigned char* packet_msg) {
    write_timestamp(log);
    int res = count_parts(packet_msg);
    unsigned char domain[128];
    get_domain(domain, packet_msg, res);
    fprintf(log, "requested %s\n", domain);
    fflush(log);
}

// Merge packet_len and packet_msg
void merge_packet(unsigned char* packet, unsigned char* packet_len, unsigned char* packet_msg, int len) {
    packet[0] = packet_len[0];
    packet[1] = packet_len[1];

    int i;
    for (i=2; i<len; i++) {
        packet[i] = packet_msg[i-2];
    }
    packet[i] = '\0';
}

// Update log when there is a response
void response_log(FILE* log, unsigned char* packet_msg) {
    int pos = get_type_index(packet_msg) + 6;
    if (is_IPV6(packet_msg, pos)) {
        // Add time stamp and domain to log
        write_timestamp(log);
        unsigned char domain[128];
        get_domain(domain, packet_msg, count_parts(packet_msg));
        fprintf(log, "%s is at ", domain);

        // Retrieve IPV6 address
        pos += 10;
        char IPV6_addr[256];
        inet_ntop(AF_INET6, packet_msg+pos, IPV6_addr, 256);
        fprintf(log, "%s\n", IPV6_addr);
        fflush(log);
    } else {
        return;
    }
}

// Update log when the request is not IPV6
void non_IPV6_log(FILE* log) {
    write_timestamp(log);
    fprintf(log, "unimplemented request\n");
    fflush(log);
}

/**********************************************************/
// Functions for cache

// Get ttl of an answer
int get_ttl(unsigned char* packet_msg) {
    int pos = get_type_index(packet_msg) + 10;
    int ttl = packet_msg[pos+3];
    ttl += packet_msg[pos+2] << 8;
    ttl += packet_msg[pos+1] << 16;
    ttl += packet_msg[pos] << 24;
    return ttl;
}

// Check if the cache is expired
int expired(cache_t* cache_info) {
    time_t curr_time;
    time(&curr_time);
    if (cache_info->expire <= curr_time) {
        return 1;
    }
    return 0;
}

// Create new cache info
cache_t* new_cache_info(unsigned char* packet_len, unsigned char* packet_msg, int ttl) {
    time_t create;
    time_t expire;
    time(&create);
    expire = create + ttl;
    cache_t* cache_info = malloc(sizeof(cache_t));
    cache_info->expire = expire;
    cache_info->packet_len = packet_len;
    cache_info->packet_msg = packet_msg;
    return cache_info;
}

// Determine which part of cache should be evicted
int get_evict_pos(cache_t* cache[]) {
    int pos = 0;
    if (cache[0] == NULL) {
        return pos;
    }
    int i;
    time_t expire;
    time_t first_expire = cache[0]->expire;

    for (i=0; i<CACHE_BUFFER; i++) {
        if (cache[i] == NULL) {
            return i;
        }
        expire = cache[i]->expire;

        if (expired(cache[i])) {
            return i;
        }

        if (expire < first_expire) {
            pos = i;
            first_expire = expire;
        }
    }
    return pos;
}

// Update cache
void update_cache(cache_t* cache[], unsigned char* packet_len, unsigned char* packet_msg, FILE* log) {
    // Check ANCOUNT is not 0
    if (!packet_msg[7]) {
        return;
    }
    int ttl = get_ttl(packet_msg);
    cache_t* new_answer = new_cache_info(packet_len, packet_msg, ttl);
    // Determine which part to insert
    int pos = get_evict_pos(cache);
    // Cache eviction and log update
    if (cache[pos] != NULL) {
        unsigned char org_domain[128];
        get_domain(org_domain, cache[pos]->packet_msg, count_parts(cache[pos]->packet_msg));
        // Get new domain;
        unsigned char new_domain[128];
        get_domain(new_domain, packet_msg, count_parts(packet_msg));
        // Update log
        write_timestamp(log);
        fprintf(log, "replacing %s by %s\n", org_domain, new_domain);
        fflush(log);
        free(cache[pos]);
    }
    // Insert new answer
    cache[pos] = new_answer;
}

// Free cache
void free_cache(cache_t* cache[]) {
    for (int i=0; i<CACHE_BUFFER; i++) {
        free(cache[i]);
    }
}

// Compare two packets
int cmp_packet(unsigned char* cache_packet, unsigned char* req_packet) {
    int pos = INIT;
    while (cache_packet[pos] != 0 && req_packet[pos] != 0) {
        if (cache_packet[pos] != req_packet[pos]) {
            return 0;
        }
        pos++;
    }
    if (cache_packet[pos] == 0 && req_packet[pos] == 0) {
        return 1;
    }
    return 0;
}

// Search from cache
cache_t* search_cache(cache_t* cache[], unsigned char* packet_msg) {
    for (int i=0; i<CACHE_BUFFER; i++) {
        if (cache[i] != NULL && !expired(cache[i]) && cmp_packet(cache[i]->packet_msg, packet_msg)) {
            // Update packetID
            cache[i]->packet_msg[0] = packet_msg[0];
            cache[i]->packet_msg[1] = packet_msg[1];

            // Update TTL
            time_t curr_time;
            time(&curr_time);
            long new_ttl = cache[i]->expire - curr_time;
            int pos = get_type_index(packet_msg) + 10;
            cache[i]->packet_msg[pos] = new_ttl >> 24;
            cache[i]->packet_msg[pos+1] = new_ttl >> 16;
            cache[i]->packet_msg[pos+2] = new_ttl >> 8;
            cache[i]->packet_msg[pos+3] = new_ttl;
            return cache[i];
        }
    }
    return NULL;
}

// Update log when there is a match in cache
void cache_log(FILE* log, cache_t* result) {
    write_timestamp(log);
    unsigned char domain[128];
    get_domain(domain, result->packet_msg, count_parts(result->packet_msg));
    fprintf(log, "%s expires at ", domain);
    time_t expire = result->expire;
    struct tm* expire_info;
    expire_info = localtime(&expire);
    char res[100];
    strftime(res, 100, "%FT%T%z", expire_info);
    fprintf(log, "%s\n", res);

    // Retrieve IPV6 address
    write_timestamp(log);
    fprintf(log, "%s is at ", domain);
    int pos = get_type_index(result->packet_msg) + 16;
    char IPV6_addr[256];
    inet_ntop(AF_INET6, result->packet_msg+pos, IPV6_addr, 256);
    fprintf(log, "%s\n", IPV6_addr);
    fflush(log);
}
