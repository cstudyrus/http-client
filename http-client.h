#ifndef _HTTP_CLIENT_H_
#define _HTTP_CLIENT_H_

#include<stddef.h>
#include<unistd.h>
#include<openssl/bio.h>
#include<openssl/ssl.h>
#include<arpa/inet.h>
#include<pthread.h>

#define HTTP_CONNECTION_INVALID NULL

#define HTTP_SSL_USE 0x0001
#define HTTP_SSL_VERIFY_SERVER_CERT 0x0002

enum CONNECTION_STATE{READY, NOT_READY};
enum LOAD_MODE{FREE,LENGTH,CHUNK};

struct __HTTP_connection{
	int socket_fd;
	int domain;
	enum CONNECTION_STATE state;
	BIO *bio;
	int use_ssl;
	SSL *ssl;
};
typedef struct __HTTP_connection* HTTP_connection;

struct __HTTP_request{
	unsigned char *buf;
	unsigned char *cur;
	size_t buf_sz;
	size_t cur_sz;
};
typedef struct __HTTP_request HTTP_request;


typedef char http_string_t[4096];

struct buffer_chunk_deskriptor;
struct http_buffer{
	unsigned char *buf;
	size_t buf_sz;

	struct http_buffer *next, *prev;

	struct buffer_chunk_deskriptor *ch_d;
	int save_ready;
};

struct __HTTP_response{
	struct http_buffer *buffer;
	struct http_buffer *cur_buffer;
	size_t cur_buffer_sz;

	unsigned short code;
	char code_text[65];
	struct http_buffer *header_end_buffer;
	unsigned char *header_end;
	struct http_buffer *status_line_buffer;
	unsigned char *status_line_end;
	http_string_t headers[128];
	int headers_num;

	enum LOAD_MODE mode;
	ssize_t read;

	size_t content_length;

	ssize_t chunk_size;
	size_t old_chunk_sum;
	struct http_buffer *chunk_buffer;
	unsigned char *chunk_start;
	int do_chunk_skip;
	int first_chunk;

	size_t ch_num;
};
typedef struct __HTTP_response HTTP_response;

struct __HTTP_response_fd{
	int *fd;
	pthread_mutex_t fd_mtx;
	pthread_cond_t fd_cv;
};
typedef struct __HTTP_response_fd HTTP_response_fd;

HTTP_response_fd http_response_fd_create(int*);
void http_response_fd_destroy(HTTP_response_fd*);

HTTP_connection http_create_connection(const struct sockaddr*, int);
void http_shutdown_connection(HTTP_connection);
int http_send_request(HTTP_connection, const HTTP_request*);
int http_get_response(HTTP_connection, HTTP_response*);

//ssize_t get_ipv4_address(struct in_addr*, size_t, const char*);

int http_request_alloc(HTTP_request*, size_t);
void http_request_free(HTTP_request*);
int http_request_set_method(HTTP_request*, const char*, const char*, const char*);
int http_request_add_header(HTTP_request*, const char*, const char*);
int http_request_close_header(HTTP_request*);

int http_response_alloc(HTTP_response*, size_t);
void http_response_free(HTTP_response*);
int http_response_find_header_end(HTTP_response*);
int http_response_get_code(HTTP_response*);
int http_response_add_mem_block(HTTP_response*);
int http_response_parse_header(HTTP_response*);
size_t http_response_get_header_size(const HTTP_response*);
int http_response_get_chunk_size(HTTP_response*);
int http_response_set_rest(HTTP_response*);
void http_response_chunk_shift(HTTP_response*);

//void http_response_body_save(HTTP_response*, int);
int http_response_body_save(HTTP_connection, HTTP_response*, HTTP_response_fd*);

int base64_encode(unsigned char*, size_t, const unsigned char*, size_t);
ssize_t base64_decode(unsigned char*, size_t, const unsigned char*);

#endif /* _HTTP_CLIENT_H_ */
