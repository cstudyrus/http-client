#include"url.h"

#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<arpa/inet.h>
#include<strings.h>
#include<stdlib.h>
#include<sys/uio.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/select.h>
#include<errno.h>
#include<ctype.h>

#include<openssl/bio.h>
#include<openssl/ssl.h>

#include<string.h>
#include<assert.h>

enum LOAD_MODE{FREE,LENGTH,CHUNK};

struct __HTTP_request{
	unsigned char *buf;
	unsigned char *cur;
	size_t buf_sz;
	size_t cur_sz;
};
typedef struct __HTTP_request HTTP_request;

/*struct http_string{
	char *start;
	size_t sz;
};*/
typedef char http_string_t[4096];

struct http_buffer{
	unsigned char *buf;
	size_t buf_sz;

	struct http_buffer *next;
};

struct __HTTP_response{
	struct http_buffer *buffer;
	struct http_buffer *cur_buffer;
	size_t cur_buffer_sz;

//	char code[4];
	struct http_buffer *header_end_buffer;
	unsigned char *header_end;
	struct http_buffer *status_line_buffer;
	unsigned char *status_line_end;
//	struct http_string headers[128];
	http_string_t headers[128];
	int headers_num;

	enum LOAD_MODE mode;
	ssize_t rest;
	ssize_t read;

//	int is_chunk;
	ssize_t chunk_size;
	size_t old_chunk_sum;
	struct http_buffer *chunk_buffer;
	unsigned char *chunk_start;
	int do_chunk_skip;
	int first_chunk;

//	unsigned char *ch_st;
	size_t ch_num;
//	size_t df;
};
typedef struct __HTTP_response HTTP_response;

ssize_t get_ipv4_address(struct in_addr*, size_t, const char*);

int http_request_alloc(HTTP_request*, size_t);
void http_request_free(HTTP_request*);
int http_request_set_method(HTTP_request*, const char*, const char*, const char*);
int http_request_add_header(HTTP_request*, const char*, const char*);
int http_request_close_header(HTTP_request*);

int http_response_alloc(HTTP_response*, size_t);
void http_response_free(HTTP_response*);
int http_response_find_header_end(HTTP_response*);
int http_response_add_mem_block(HTTP_response*);
int http_response_parse_header(HTTP_response*);
size_t http_response_get_header_size(const HTTP_response*);
int http_response_get_chunk_size(HTTP_response*);
int http_response_set_rest(HTTP_response*);
void http_response_chunk_shift(HTTP_response*);

int base64_encode(unsigned char*, size_t, const unsigned char*, size_t);
ssize_t base64_decode(unsigned char*, size_t, const unsigned char*);

int main(int argc, char **argv)
{
	char host_name[1024] = "www.skydns.ru";
	char path[1024] = {'/','\0'};
	struct in_addr addresses[16];
	char ipv4_addr[16] = {'\0'};
	ssize_t num, i;
	HTTP_request request;
	HTTP_response response;
	int sock;
	struct sockaddr_in server_addr;
	struct iovec out_blocks[16];
	struct iovec in_blocks[16];

	int fcntl_flags;
	int connect_res;
	fd_set rset, wset;
	ssize_t readv_res;
	struct http_buffer *current_buffer;
	int auth_need = 0;
	char auth_string[1024] = "\0";
	char cred_string[1024] = "\0";
	char username[] = "skydns";
	char password[] = "dns1356";

	char request_str[200000] = {'\0'};
	char *request_str_p;

	BIO *connection;
	SSL *ssl;
	SSL_CTX *ctx;

	SSL_library_init();
	ctx = SSL_CTX_new(TLS_client_method());
int end_flag = 0;
	if(argc < 2)
	{
		printf("Usage: %s <url>\n", argv[0]);
		return 1;
	}

//	url_get_host(host_name, 1024, argv[1]);



	num = get_ipv4_address(addresses, 16, host_name);
	inet_ntop(AF_INET, addresses, ipv4_addr, sizeof(ipv4_addr));


	if(!num)
	{
		printf("Unable to resolve hostname %s\n", host_name);
		return 2;
	}

/*	server_addr.sin_family = AF_INET;
	server_addr.sin_addr = addresses[0];
	server_addr.sin_port = htons(80);

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("Unable to create socket\n");
		return 2;
	}*/

	connection = BIO_new_connect(ipv4_addr);
	if(!connection)
	{
		printf("Can not create BIO connection\n");
		exit(1);
	}
	printf("BIO connection object was created\n");

	BIO_set_conn_port(connection, "443");
	printf("BIO connection object port was set\n");

//	sock = BIO_get_fd(connection, NULL);

/*	fcntl_flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, fcntl_flags | O_NONBLOCK);*/

	BIO_do_connect(connection);
	if((ssl = SSL_new(ctx)) == NULL)
	{
		printf("Can not create SSL connection object\n");
		exit(1);
	}
	printf("SSL connection object was created\n");

	SSL_set_bio(ssl, connection, connection);
	if((SSL_connect(ssl)) < 1)
	{
		printf("Can not pass SSL handshake\n");
		exit(1);
	}
	printf("SSL handshake was successfully passed\n");


	sock = BIO_get_fd(connection, NULL);
	fcntl_flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, fcntl_flags | O_NONBLOCK);

/*	if((connect_res = connect(sock, (const struct sockaddr*)&server_addr, sizeof(struct sockaddr_in)))
			&& errno != EINPROGRESS)
	{
		printf("Unable to connect to the server\n");
		return 2;
	}*/


	/* //////////////// Подготовка запроса ///////////////////////////////// */
	http_request_alloc(&request, 8191);

//	url_get_path(path, 1024, argv[1]);

	http_request_set_method(&request, "GET", "1.1", path);
	http_request_add_header(&request, "Host", host_name);
	http_request_add_header(&request, "User-Agent", "liburl2cat");
	if((auth_need))
	{
		strcpy(cred_string, username);
		strcat(cred_string, ":");
		strcat(cred_string, password);
		strcpy(auth_string, "Basic ");
		base64_encode(auth_string + strlen("Basic "),1024,cred_string,strlen(cred_string));

		http_request_add_header(&request, "Authorization", auth_string);
	}
	http_request_add_header(&request, "Accept", "*/*");
	http_request_close_header(&request);
	/* //////////////////////////////////////////////// */

	/* ////////// Ожидание завершения соединения ///////////////// */
	if(connect_res)
	{
		FD_ZERO(&rset);
		FD_ZERO(&wset);

		FD_SET(sock, &rset);
		wset = rset;

		pselect(sock + 1, &rset, &wset, NULL, NULL, NULL);
		if(!FD_ISSET(sock, &rset) && !FD_ISSET(sock, &wset))
		{
			printf("Unable to connect to the server AGAIN\n");
			return 2;
		}
	}
	/* //////////////////////////////////// */

	/* ///////////// Отправка запроса /////////////////// */
/*	out_blocks[0].iov_base = request.buf;
	out_blocks[0].iov_len = request.buf_sz - request.cur_sz;

	writev(sock, out_blocks, 1);*/
	SSL_write(ssl, request.buf, request.buf_sz - request.cur_sz);

	http_request_free(&request);
	/* //////////////////////////////////////////////// */


	http_response_alloc(&response,10);
	FD_ZERO(&rset);
	FD_SET(sock, &rset);
	pselect(sock + 1, &rset, NULL, NULL, NULL, NULL);
	if(FD_ISSET(sock, &rset))
	{
		while(1)
		{
/*			in_blocks[0].iov_base = response.cur_buffer->buf + (response.cur_buffer->buf_sz - response.cur_buffer_sz);
			in_blocks[0].iov_len = response.cur_buffer_sz;
			*/

			FD_ZERO(&rset);
			FD_SET(sock, &rset);

			if(!SSL_pending(ssl))
				pselect(sock + 1, &rset, NULL, NULL, NULL, NULL);
//			readv_res = readv(sock, in_blocks, 1);
			readv_res = SSL_read(ssl, response.cur_buffer->buf + (response.cur_buffer->buf_sz - response.cur_buffer_sz), response.cur_buffer_sz);
			while(readv_res < 0)
			{
				int ssl_error;
				ssl_error = SSL_get_error(ssl,readv_res);
				if(ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
					readv_res = SSL_read(ssl, response.cur_buffer->buf + (response.cur_buffer->buf_sz - response.cur_buffer_sz), response.cur_buffer_sz);
				else
				{
					// ERROR!!!
					int a = 0;
				}
			}

//if(response.rest > 0 && readv_res > response.rest)
/*if(readv_res == 5)
{
	int a = 0;
	printf("OOPS!!!");
}*/
/*if(response.rest <= 0)
{
	int a = 9;
}*/
//int d;
//printf("%i %i\n",response.rest, readv_res);

			response.cur_buffer_sz -= readv_res;
			response.read += readv_res;
			if(response.rest > 0 && response.rest >= readv_res)
				response.rest -= readv_res;
			else if(response.rest > 0)
			{
				response.rest -= readv_res;
			}
			else
				;

			if(!response.headers_num)
				if(http_response_find_header_end(&response) < 0)
				{
					printf("Error of response header end\n");
					exit(-18);
				}

			if(response.mode == CHUNK && /*response.rest < 0*/ response.read >= response.ch_num)
			{
/*unsigned char *tmp;
struct http_buffer* current_buffer = response.buffer;
tmp = current_buffer->buf;
size_t bs = 0;
for(int j =0; j< response.ch_num; ++j)
{
	if(bs == current_buffer->buf_sz)
	{
		current_buffer=current_buffer->next;
		if(current_buffer == NULL)
				break;
		bs = 0;
		tmp = current_buffer->buf;
	}
	else
		++tmp;
	++bs;
}
printf("\n$$$ Last char: %c\n\n", *(tmp));

printf("$$$ Header size: %u\n", http_response_get_header_size(&response));
struct http_buffer* current_buffer2 = response.buffer;
unsigned char* tmp2 = current_buffer2->buf;
bs = 0;
for(int j =0; j< http_response_get_header_size(&response); ++j)
{
//printf("%c", *tmp2);
if(isalnum(*tmp2))
printf("j=%i, *tmp2=%c\n", j, *tmp2);
else
printf("j=%i, *tmp2=\\%hhx\n", j, *tmp2);

	if(bs == current_buffer2->buf_sz -1)
	{
		current_buffer2=current_buffer2->next;
		if(current_buffer2 == NULL)
			break;
		bs = 0;
		tmp2 = current_buffer2->buf;


	}
	else
		++tmp2;
	++bs;

}
printf("\n$$$ Header end: %hhx\n\n", (*(response.header_end)));
printf("Diference: %u\n", response.header_end - response.header_end_buffer->buf);
for(int j=0; j<10; ++j)
	if(isalnum(response.header_end[j]))
	printf("j=%i, *tmp2=%c\n", j, response.header_end[j]);
	else
	printf("j=%i, *tmp2=\\%hhx\n", j, response.header_end[j]);
//exit(-12);
 */

/*				if(response.chunk_size > 0)
				{
					if(response.chunk_size < (size_t)(response.chunk_buffer->buf_sz -(response.chunk_start - response.chunk_buffer->buf)))
						response.chunk_start += response.chunk_size;
					else
					{
						response.chunk_size -= (size_t)(response.chunk_buffer->buf_sz -(response.chunk_start - response.chunk_buffer->buf));
						response.chunk_buffer = response.chunk_buffer->next;

						while(response.chunk_size >= response.chunk_buffer->buf_sz)
						{
							response.chunk_size -= response.chunk_buffer->buf_sz;
							response.chunk_buffer = response.chunk_buffer->next;
						}
						response.chunk_start = response.chunk_buffer->buf + response.chunk_size;
					}
				}*/

				if(response.do_chunk_skip)
					http_response_chunk_shift(&response);

				if(http_response_get_chunk_size(&response))
				{
					if(response.cur_buffer_sz == 0)
						http_response_add_mem_block(&response);
					continue;
				}
/*printf("Chunk size: %i\n", response.chunk_size);
printf("Rest size: %i\n", response.rest);*/
//				exit(27);
			}

			// Это ОБЯЗАТЕЛЬНО(!!!) должно быть на последнем месте.
			if(response.rest > 0 && response.cur_buffer_sz)
				continue;
			else if(response.rest > 0)
				http_response_add_mem_block(&response);
			else if(response.mode == LENGTH)
			{
				printf("AGA!\n");
				break;
			}
			else if(response.mode == CHUNK && response.rest == 0 && response.chunk_size == 0)
				break;
			else if(response.cur_buffer_sz)
				continue;
			else
				http_response_add_mem_block(&response);
		}

		current_buffer = response.buffer;
		request_str_p = request_str;
		ssize_t rest_copy = response.read;
		while(current_buffer != NULL)
		{
			if(current_buffer->next != NULL)
			{
				memcpy(request_str_p, current_buffer->buf, current_buffer->buf_sz);
				rest_copy -= current_buffer->buf_sz;
				request_str_p += current_buffer->buf_sz;
			}
			else
				memcpy(request_str_p, current_buffer->buf, rest_copy);
//			request_str_p += current_buffer->buf_sz;
			current_buffer = current_buffer->next;
		}
		request_str[response.read] = 0;

		puts(request_str);
	}

//printf("qwwe\n\nch_num: %i, %s\n", response.ch_num, request_str+response.ch_num-1);

	http_response_free(&response);

	BIO_free(connection);
	return 0;
}

ssize_t get_ipv4_address(struct in_addr *buf, size_t n, const char *host_name)
{
	struct addrinfo addr_hint;
	struct addrinfo *lookup_res;
	ssize_t result = 0;
	struct in_addr tmp;

	addr_hint.ai_family = AF_INET;
	addr_hint.ai_socktype = 0;
	addr_hint.ai_protocol = 0;
	addr_hint.ai_flags = AI_ADDRCONFIG;

	getaddrinfo(host_name, NULL, &addr_hint, &lookup_res);

	while(lookup_res != NULL && result < n)
	{
		tmp = ((struct sockaddr_in*)(lookup_res->ai_addr))->sin_addr;
		if(result == 0 || bcmp(&buf[result-1],&tmp, sizeof(struct in_addr)))
			buf[result++] = tmp;

		lookup_res = lookup_res->ai_next;
	}

	return result;
}

int http_request_alloc(HTTP_request *request, size_t n)
{
	if((request->cur = request->buf = (unsigned char*)malloc(n)) == NULL)
		return 1;

	request->cur_sz = request->buf_sz = n;

	return 0;
}

void http_request_free(HTTP_request *request)
{
	request->cur_sz = request->buf_sz = 0;
	free(request->buf);
	request->buf = request->cur = NULL;
}

int http_request_set_method(HTTP_request *request, const char *method, const char *version, const char *resourse)
{
	const char HTTP[] = "HTTP/";
	const char *HTTP_p = HTTP;

	while(*method && request->cur_sz)
	{
		*request->cur++ = *method++;
		--request->cur_sz;
	}

	if(!request->cur_sz)
		return 1;
	*request->cur++ = ' ';
	--request->cur_sz;


	while(*resourse && request->cur_sz)
	{
		*request->cur++ = *resourse++;
		--request->cur_sz;
	}
	if(!request->cur_sz)
		return 1;
	*request->cur++ = ' ';
	--request->cur_sz;


	if(request->cur_sz < sizeof(HTTP) - 1)
		return 1;
	while(*HTTP_p)
	{
		*request->cur++ = *HTTP_p++;
		--request->cur_sz;
	}

	while(*version && request->cur_sz)
	{
		*request->cur++ = *version++;
		--request->cur_sz;
	}

	if(request->cur_sz < 2)
		return 1;

	*request->cur++ = '\r';
	*request->cur++ = '\n';
	request->cur_sz -= 2;

	return 0;
}

int http_request_add_header(HTTP_request *request, const char *field_name, const char *field_value)
{
	while(*field_name && request->cur_sz)
	{
		*request->cur++ = *field_name++;
		--request->cur_sz;
	}

	if(request->cur_sz < 2)
		return 1;
	*request->cur++ = ':';
	*request->cur++ = ' ';
	request->cur_sz -= 2;

	while(*field_value && request->cur_sz)
	{
		*request->cur++ = *field_value++;
		--request->cur_sz;
	}

	if(request->cur_sz < 2)
		return 1;
	*request->cur++ = '\r';
	*request->cur++ = '\n';
	request->cur_sz -= 2;

	return 0;
}

int http_request_close_header(HTTP_request *request)
{
	if(request->cur_sz < 2)
		return 1;

	*request->cur++ = '\r';
	*request->cur++ = '\n';
	request->cur_sz -= 2;

	return 0;
}

int http_response_alloc(HTTP_response *response, size_t n)
{
	if((response->cur_buffer = response->buffer = (struct http_buffer*)malloc(sizeof(struct http_buffer))) == NULL)
		return 1;
	if((response->buffer->buf = (unsigned char*)malloc(n)) == NULL)
	{
		free(response->buffer);
		return 1;
	}

	response->buffer->buf_sz = n;
	response->buffer->next = NULL;

//	response->cur_sz = response->buf_sz = n;
	response->cur_buffer_sz = n;
	response->header_end_buffer = NULL;
	response->header_end = NULL;
	response->status_line_buffer = NULL;
	response->status_line_end = NULL;
	response->rest = -1;
	response->read = 0;
	response->mode = FREE;
	response->headers_num = 0;

	response->chunk_buffer = NULL;
	response->chunk_size = -1;
	response->old_chunk_sum = 0;
	response->chunk_start = NULL;
	response->do_chunk_skip = 0;
	response->first_chunk = 1;

	return 0;
}

void http_response_free(HTTP_response *response)
{
/*	response->cur_sz = response->buf_sz = 0;
	response->header_end = NULL;
	free(response->buf);*/
	struct http_buffer *tmp;

	while(response->buffer != NULL)
	{
		free(response->buffer->buf);
		tmp = response->buffer;
		response->buffer = response->buffer->next;
		free(tmp);

	}
}


int http_response_find_header_end(HTTP_response *response)
{
	register struct http_buffer* current_buffer = response->buffer;
	register unsigned char *current = response->buffer->buf;
	register size_t num = 0;
	register unsigned char prev[2] = {0};

	while(current_buffer != NULL)
	{
		while(num < current_buffer->buf_sz && (*current != '\n' || prev[0] != '\r'))
		{
			prev[1] = prev[0];
			prev[0] = *current++;
			++num;
		}

		if(num == current_buffer->buf_sz)
		{
			current_buffer = current_buffer->next;
			if(current_buffer != NULL)
				current = current_buffer->buf;
			num = 0;
		}
		else
			break;
	}
	if(current_buffer == NULL || (current == current_buffer->buf + current_buffer->buf_sz - 1 && current_buffer->next == NULL))
		return 1; // Считана только status line, и всё.
	else if(current == current_buffer->buf + current_buffer->buf_sz - 1)
	{
		current_buffer = response->status_line_buffer = current_buffer->next;
		current = response->status_line_end = current_buffer->buf;
		num = 0;
	}
	else
	{
		response->status_line_buffer = current_buffer;
		response->status_line_end = ++current;
		++num;
	}
//	++current;
//	++num;
	while(current_buffer != NULL)
	{

		while(num < current_buffer->buf_sz)
			if(prev[1] == '\r' && prev[0] == '\n' &&
				*current == '\r' && *(current + 1) == '\n')
			{
				response->header_end_buffer = current_buffer;
				response->header_end = current;
				response->headers_num = http_response_parse_header(response);
				if(http_response_set_rest(response))
					return -1;

				return 0;
			}
			else
			{
				++num;
				prev[1] = prev[0];
				prev[0] = *current++;
			}

		current_buffer = current_buffer->next;
		if(current_buffer != NULL)
		{
			current = current_buffer->buf;
			num = 0;
		}
	}

	return 1;
}

int http_response_parse_header(HTTP_response *response)
{
	register size_t index = 0;
	register struct http_buffer* current_buffer = response->status_line_buffer;
	register unsigned char *current = response->status_line_end;
	register unsigned char *prev = NULL;
	size_t i = 0, num = 0;

	num = (size_t)(current - current_buffer->buf);
	while(current_buffer != response->header_end_buffer || current != response->header_end)
	{
		while((*current != '\n' || *prev != '\r') && num < current_buffer->buf_sz)
		{
			response->headers[index][i++] = *current;
			prev = current++;
			++num;
		}
		if((*current == '\n' && *prev == '\r'))
		{
			prev = current;
			response->headers[index][i-1] = '\0';
			++index;
			++current;
			i = 0;
			++num;
		}

	if(num == current_buffer->buf_sz)
		{
			num = 0;
			prev = current-1;
			current_buffer = current_buffer->next;
			if(current_buffer != NULL)
				current = current_buffer->buf;
		}
	}

	return index;
}

size_t http_response_get_header_size(const HTTP_response *response)
{
	size_t result = 0;
	register struct http_buffer* current_buffer = response->buffer;

	while(current_buffer != response->header_end_buffer)
	{
		result += current_buffer->buf_sz;
		current_buffer = current_buffer->next;
	}
	result += (size_t)(response->header_end - response->header_end_buffer->buf);

	return result;
}

static int http_response_get_chunk_size_load(HTTP_response *response, size_t n)
{
	register struct http_buffer* current_buffer;
	register unsigned char *current;
	size_t num, i;
	register size_t tmp = 0;

	response->chunk_size = 0;

	current_buffer = response->chunk_buffer;
	current = response->chunk_start;

	num = (size_t)(current - current_buffer->buf);
	for(i=0; i<n; ++i)
	{
		if(*current >= '0' && *current <= '9')
			tmp = *current++ - '0';
		else if (*current >= 'A' && *current <= 'F')
			tmp = *current++ - 'A' + 10;
		else if (*current >= 'a' && *current <= 'f')
			tmp = *current++ - 'a' + 10;
		else
			return 1;
		response->chunk_size += tmp << ((n-1-i) << 2);

		++num;
		if(num == current_buffer->buf_sz)
		{ //Переключаемся на следующий буфер.
			num = 0;
			current_buffer = current_buffer->next;
			current = current_buffer->buf;
		}
	}

	response->chunk_size += 2 + 2; // 3 - это CRLF и первый символ нового chunk size, 2 - это CRLF в конце chunk.

	return 0;
}

int http_response_get_chunk_size(HTTP_response *response)
{
	register struct http_buffer* current_buffer;
	register unsigned char *current;
	register unsigned char *prev = NULL;
	size_t num, index = 0;
	size_t rest_chunk_size;

	if(response->chunk_buffer != NULL)
	{
		current_buffer = response->chunk_buffer;
		current = response->chunk_start;

		num = (size_t)(current - current_buffer->buf);
while(1){
		while((prev == NULL || *current != '\n' || *prev != '\r') && num < current_buffer->buf_sz)
		{
			prev = current++;
			++num;
			++index;
		}
		if((*current == '\n' && *prev == '\r'))
		{
			// Нашли конец строки chunk size.
			--index;

			if(response->chunk_size > 0)
				response->old_chunk_sum += response->chunk_size/* + index*/;

			if(http_response_get_chunk_size_load(response, index))
				return 2; // Недопустимый символ в chunk size.
// Обработать случай chunk size = 0.

			if(response->chunk_size == 4)
			{
//				response->mode = FREE;
				response->rest = 0;
				response->chunk_size = 0;
				return 0;
			}

			if(response->read - response->old_chunk_sum <= response->chunk_size)
			{
				if(response->first_chunk)
				{
//response->ch_st =response->chunk_start;

//size_t df;
//response->df = http_response_get_header_size(response)+2;
response->ch_num = http_response_get_header_size(response)+2;
// response->rest = response->chunk_size - (response->read - response->ch_num) + 1 + index;
 response->ch_num += response->chunk_size + 1 + index;
//					response->rest = response->chunk_size - (response->read - response->old_chunk_sum) + 1 + index -1;
					response->first_chunk = 0;
//					response->chunk_size += index-1;
				}
else{
//				response->rest = response->chunk_size - (response->read - response->old_chunk_sum) + 1;
response->ch_num += response->chunk_size + index;
}
/*if(response->read - response->old_chunk_sum == response->chunk_size)
	printf("##EQ!!\n");
printf("##Read: %i\n", response->read);
printf("##Index: %i\n", index);
printf("##Rest Size: %i\n", response->rest);*/
				response->chunk_size += index;
			}
			else
			{
				// Этот chunk уже полностью загружен. Переходим к следующему.
//				if(index + response->chunk_size < response->chunk_buffer->buf_sz)
				if(index + response->chunk_size < response->chunk_buffer->buf_sz - (size_t)(response->chunk_start - response->chunk_buffer->buf))
					response->chunk_start += index + response->chunk_size;
				else
				{
					response->chunk_size -= response->chunk_buffer->buf_sz - (size_t)(response->chunk_start - response->chunk_buffer->buf);
response->old_chunk_sum += response->chunk_buffer->buf_sz - (size_t)(response->chunk_start - response->chunk_buffer->buf);
					response->chunk_buffer = response->chunk_buffer->next;

					while(index + response->chunk_size >= response->chunk_buffer->buf_sz)
					{
						response->chunk_size -= response->chunk_buffer->buf_sz;
response->old_chunk_sum += response->chunk_buffer->buf_sz;
						response->chunk_buffer = response->chunk_buffer->next;
					}
					response->chunk_start = response->chunk_buffer->buf + index + response->chunk_size;
				}


				return http_response_get_chunk_size(response);
			}

			response->do_chunk_skip = 1;
			return 0; // ВСЁ!
		}
		if(num == current_buffer->buf_sz)
		{ //Переключаемся на следующий буфер.
			num = 0;
			prev = current-1;
			current_buffer = current_buffer->next;
			if(current_buffer != NULL)
				current = current_buffer->buf;
			else
			{
				response->do_chunk_skip = 0;
				return 1; // А следующего-то и нет!!! Дозагружаемся.
			}
		}
	}
}
	else
		return 1; // Дозагружаемся.
}

int http_response_set_rest(HTTP_response *response)
{
	size_t i;
	const char content_length[] = "Content-Length:";
	const char transfer_encoding[] = "Transfer-Encoding:";
	const char chunk[] = "chunked";
	register char *tmp;
	int cl;

	for(i=0; i<response->headers_num; ++i)
	{
		if(!strncasecmp(response->headers[i], transfer_encoding, sizeof(transfer_encoding) - 1))
		{
			if(strstr(response->headers[i] + sizeof(transfer_encoding) - 1, chunk) != NULL)
			{
				response->mode = CHUNK;
				response->old_chunk_sum += http_response_get_header_size(response)+2+1; // CRLF и первый символ первого chunk size.
				if(response->header_end_buffer->buf_sz - (size_t)(response->header_end - response->header_end_buffer->buf) > 2)
				{
					// В response->header_end_buffer есть место под chunk size.
					response->chunk_buffer = response->header_end_buffer;
					response->chunk_start = response->header_end + 2;
				}
				else if(response->header_end_buffer->next != NULL)
				{
					// В следующем после response->header_end_buffer есть место под chunk size.
					response->chunk_buffer = response->header_end_buffer->next;
					response->chunk_start = response->chunk_buffer->buf +
							(size_t)(response->header_end - response->header_end_buffer->buf) - response->header_end_buffer->buf_sz + 2;
				}
				else
					; // Нет места под chunk size.

				return 0;
			}

			else
				break;
		}
	}

	for(i=0; i<response->headers_num; ++i)
	{
		if(!strncasecmp(response->headers[i], content_length, sizeof(content_length) - 1))
		{
			tmp = response->headers[i] + sizeof(content_length) - 1;
			while(*tmp == ' ')
				++tmp;
			cl = strtol(tmp, NULL, 10);
			response->rest = cl - (response->read - http_response_get_header_size(response) -2);
			response->mode = LENGTH;
			return 0;
		}
	}
	return 1;
}

void http_response_chunk_shift(HTTP_response* response)
{

	if(response->chunk_size > 0)
	{
		if(response->chunk_size < (size_t)(response->chunk_buffer->buf_sz -(response->chunk_start - response->chunk_buffer->buf)))
			response->chunk_start += response->chunk_size;
		else
		{
			response->chunk_size -= (size_t)(response->chunk_buffer->buf_sz -(response->chunk_start - response->chunk_buffer->buf));
response->old_chunk_sum += (size_t)(response->chunk_buffer->buf_sz -(response->chunk_start - response->chunk_buffer->buf));
			response->chunk_buffer = response->chunk_buffer->next;

			while(response->chunk_size >= response->chunk_buffer->buf_sz)
			{
				response->chunk_size -= response->chunk_buffer->buf_sz;
response->old_chunk_sum += response->chunk_buffer->buf_sz;


				response->chunk_buffer = response->chunk_buffer->next;
			}
			response->chunk_start = response->chunk_buffer->buf + response->chunk_size;
		}
	}

}

int http_response_add_mem_block(HTTP_response *response)
{
	struct http_buffer *new_buffer;
	if((new_buffer = (struct http_buffer*)malloc(sizeof(struct http_buffer))) == NULL)
		return 1;

	if((new_buffer->buf = (unsigned char*)malloc(response->cur_buffer->buf_sz)) == NULL)
	{
		free(new_buffer);
		return 1;
	}

	new_buffer->buf_sz = response->cur_buffer->buf_sz;
	new_buffer->next = NULL;

	response->cur_buffer->next = new_buffer;
	response->cur_buffer = new_buffer;
	response->cur_buffer_sz = new_buffer->buf_sz;

	return 0;
}

int base64_encode(unsigned char *dst, size_t dst_sz, const unsigned char *src, size_t src_sz)
{
	register size_t i, index = 0;

	const static unsigned char code_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	if(dst_sz < ((src_sz % 3) ? (src_sz / 3)*4 + 4 : (src_sz / 3)*4) +1)
		return 1;

	for(i=0; i <3*(src_sz / 3); i += 3)
	{
		dst[index++] = code_table[src[i] >> 2];
		dst[index++] = code_table[((src[i] & 0x03) << 4) | (src[i+1] >> 4)];
		dst[index++] = code_table[((src[i+1] & 0x0F) << 2) | (src[i+2] >> 6)];
		dst[index++] = code_table[src[i+2] & 0x3F];
	}
	switch(src_sz % 3){
	case 1:
		dst[index++] = code_table[src[i] >> 2];
		dst[index++] = code_table[((src[i] & 0x03) << 4)];
		dst[index++] = '=';
		dst[index++] = '=';
		break;
	case 2:
		dst[index++] = code_table[src[i] >> 2];
		dst[index++] = code_table[((src[i] & 0x03) << 4) | (src[i+1] >> 4)];
		dst[index++] = code_table[((src[i+1] & 0x0F) << 2)];
		dst[index++] = '=';
		break;
	default:
		break;
	}

	dst[index++] = '\0';
	return 0;
}

ssize_t base64_decode(unsigned char *dst, size_t dst_sz, const unsigned char *src)
{
	size_t res_sz;
	size_t str_len;
	register size_t i,j, index = 0;
	unsigned char tmp[4];

	str_len = strlen(src);
	res_sz = 3*(str_len/4);
	if(src[str_len - 1] == '=')
	{
		--res_sz;
		if(src[str_len - 2] == '=')
			--res_sz;
	}
	if(dst_sz < res_sz)
		return -1;

	for(i=0; i <str_len; i += 4)
	{
		for(j=0;j<4;++j)
			if(src[i+j] == '+')
				tmp[j] = 62;
			else if(src[i+j] == '/')
				tmp[j] = 63;
			else if(src[i+j] >= '0' && src[i+j] <= '9')
				tmp[j] = 52 + src[i+j] - '0';
			else if(src[i+j] >= 'a' && src[i+j] <= 'z')
				tmp[j] = 26 + src[i+j] - 'a';
			else if(src[i+j] >= 'A' && src[i+j] <= 'Z')
				tmp[j] = src[i+j] - 'A';
			else if(src[i+j] == '=')
				tmp[j] = 0;
			else
				return -1;

		dst[index++] = (tmp[0] << 2) | (tmp[1] >> 4);
		dst[index++] = (tmp[1] << 4) | (tmp[2] >> 2);
		dst[index++] = (tmp[2] << 6) | tmp[3];
	}

	return (ssize_t)index;
}

