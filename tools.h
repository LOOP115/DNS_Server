#define CACHE_BUFFER 5      // Size of cache
#define INIT 12         // Index after AR

typedef struct {
    time_t expire;
    unsigned char* packet_len;
    unsigned char* packet_msg;
} cache_t;

int get_packet_len(unsigned char* packet_len);

int get_type_index(unsigned char* packet_msg);

int is_IPV6(unsigned char* packet_msg, int pos);

void request_log(FILE* log, unsigned char* packet_msg);

void merge_packet(unsigned char* packet, unsigned char* packet_len, unsigned char* packet_msg, int len);

void response_log(FILE* log, unsigned char* packet_msg);

void non_IPV6_log(FILE* log);

void update_cache(cache_t* cache[], unsigned char* packet_len, unsigned char* packet_msg, FILE* log);

void free_cache(cache_t* cache[]);

cache_t* search_cache(cache_t* cache[], unsigned char* packet_msg);

void cache_log(FILE* log, cache_t* result);
