int create_server_socket(const char* port);

int create_client_socket(const char* address, const char* port);

void safe_read(int sockfd, unsigned char* packet, int len);
