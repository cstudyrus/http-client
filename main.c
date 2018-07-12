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

#include<string.h>

struct __HTTP_request{
	unsigned char *buf;
	unsigned char *cur;
	size_t buf_sz;
	size_t cur_sz;
};
typedef struct __HTTP_request HTTP_request;

struct http_string{
	char *start;
	size_t sz;
};

struct http_buffer{
	unsigned char *buf;
	size_t buf_sz;

	struct http_buffer *next;
};

struct __HTTP_response{
//	unsigned char *buf;
	struct http_buffer *buffer;
//	unsigned char *cur;
	struct http_buffer *cur_buffer;
//	size_t buf_sz;
//	size_t cur_sz;
	size_t cur_buffer_sz;

//	char code[4];
	struct http_buffer *header_end_buffer;
	unsigned char *header_end;
	struct http_string headers[128];
	ssize_t rest;
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

int base64_encode(unsigned char*, size_t, const unsigned char*, size_t);
ssize_t base64_decode(unsigned char*, size_t, const unsigned char*);

int main(int argc, char **argv)
{
	char host_name[1024];
	char path[1024];
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
	int auth_need = 1;
	char auth_string[1024] = "\0";
	char cred_string[1024] = "\0";
	char username[] = "skydns";
	char password[] = "dns1356";

	char request_str[65536] = {'\0'};
	char *request_str_p;

//base64_encode(request_str,65536,"skydns:dns1356",strlen("skydns:dns1356"));
/*ssize_t index;
index = base64_decode(request_str,65536,"Zm9vYmE=");
request_str[index] = '\0';
puts(request_str);
return 0;*/

	if(argc < 2)
	{
		printf("Usage: %s <url>\n", argv[0]);
		return 1;
	}

	url_get_host(host_name, 1024, argv[1]);

/*	memcpy(request_str, request.buf, request.buf_sz - request.cur_sz);
	puts(request_str);*/

	num = get_ipv4_address(addresses, 16, host_name);

	if(!num)
	{
		printf("Unable to resolve hostname %s\n", host_name);
		return 2;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr = addresses[0];
	server_addr.sin_port = htons(80);

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("Unable to create socket\n");
		return 2;
	}

	fcntl_flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, fcntl_flags | O_NONBLOCK);

	if((connect_res = connect(sock, (const struct sockaddr*)&server_addr, sizeof(struct sockaddr_in)))
			&& errno != EINPROGRESS)
	{
		printf("Unable to connect to the server\n");
		return 2;
	}


	/* //////////////// Подготовка запроса ///////////////////////////////// */
	http_request_alloc(&request, 8191);

	url_get_path(path, 1024, argv[1]);

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
	out_blocks[0].iov_base = request.buf;
	out_blocks[0].iov_len = request.buf_sz - request.cur_sz;

	writev(sock, out_blocks, 1);

	http_request_free(&request);
	/* //////////////////////////////////////////////// */


	http_response_alloc(&response, 20);
	FD_ZERO(&rset);
	FD_SET(sock, &rset);
	pselect(sock + 1, &rset, NULL, NULL, NULL, NULL);
	if(FD_ISSET(sock, &rset))
	{
/*		in_blocks[0].iov_base = response.cur;
		in_blocks[0].iov_len = response.cur_sz;

		readv_res = readv(sock, in_blocks, 1);
		response.cur += readv_res;
		response.cur_sz -= readv_res;*/

//		while(1)
		while(response.rest)
		{
			in_blocks[0].iov_base = response.cur_buffer->buf + (response.cur_buffer->buf_sz - response.cur_buffer_sz);
			in_blocks[0].iov_len = response.cur_buffer_sz;

			readv_res = readv(sock, in_blocks, 1);
			response.cur_buffer_sz -= readv_res;

	/*		if(response.cur_buffer_sz)
				break;*/
			if(!http_response_find_header_end(&response))
				response.rest = 0;

			http_response_add_mem_block(&response);
		}

		if(http_response_find_header_end(&response))
		{
			printf("Header is not found\n");
			return -5;
		}
//		memcpy(request_str, response.buf, response.buf_sz);

		current_buffer = response.buffer;
		request_str_p = request_str;
//		while(current_buffer != response.header_end_buffer)
		while(current_buffer != NULL)
		{
			memcpy(request_str_p, current_buffer->buf, current_buffer->buf_sz);
			request_str_p += current_buffer->buf_sz;
			current_buffer = current_buffer->next;
		}
//		memcpy(request_str_p, response.header_end_buffer->buf, (size_t)(response.header_end - response.header_end_buffer->buf));

		puts(request_str);
	}

	http_response_free(&response);

/*	for(i=0; i<num; ++i)
		printf("%s\n", inet_ntop(AF_INET, addresses+i, ipv4_addr, sizeof(ipv4_addr)));
*/
//	printf("Host name: %s\n", host_name);

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
	response->rest = -1;

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

/*int http_response_find_header_end(HTTP_response *response)
{
	register unsigned char *current = response->buf;
	register size_t num = 0;

	while(num < response->buf_sz - response->cur_sz && (*current != '\n' || *(current - 1) != '\r'))
	{
		++current;
		++num;
	}

	++current;
	++num;
	while(num < response->buf_sz - response->cur_sz)
		if(*(current - 2) == '\r' && *(current - 1) == '\n' &&
				*current == '\r' && *(current + 1) == '\n')
		{
			response->header_end = current;
			return 0;
		}
		else
		{
			++num;
			++current;
		}

	return 1;
}*/

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
//			prev[2] = prev[1];
			prev[1] = prev[0];
			prev[0] = *current++;
			++num;
		}

		if(num == current_buffer->buf_sz)
		{
			current_buffer = current_buffer->next;
			current = current_buffer->buf;
			num = 0;

			continue;
		}
		else
			break;
	}

	++current;
	++num;
	while(current_buffer != NULL)
	{

		while(num < current_buffer->buf_sz)
			if(prev[1] == '\r' && prev[0] == '\n' &&
				*current == '\r' && *(current + 1) == '\n')
			{
				response->header_end_buffer = current_buffer;
				response->header_end = current;
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

