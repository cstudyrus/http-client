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

struct __HTTP_response{
	unsigned char *buf;
	unsigned char *cur;
	size_t buf_sz;
	size_t cur_sz;

//	char code[4];
	unsigned char *header_end;
	struct http_string headers[128];
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

	char request_str[1024] = {'\0'};

	if(argc < 2)
	{
		printf("Usage: %s <url>\n", argv[0]);
		return 1;
	}

	http_request_alloc(&request, 8191);

	url_get_host(host_name, 1024, argv[1]);
	url_get_path(path, 1024, argv[1]);

	http_request_set_method(&request, "GET", "1.1", path);
	http_request_add_header(&request, "Host", host_name);
	http_request_add_header(&request, "User-Agent", "liburl2cat");
	http_request_add_header(&request, "Accept", "*/*");
	http_request_close_header(&request);

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

	out_blocks[0].iov_base = request.buf;
	out_blocks[0].iov_len = request.buf_sz - request.cur_sz;

	writev(sock, out_blocks, 1);

	http_request_free(&request);


	http_response_alloc(&response, 8191);
	FD_ZERO(&rset);
	FD_SET(sock, &rset);
	pselect(sock + 1, &rset, NULL, NULL, NULL, NULL);
	if(FD_ISSET(sock, &rset))
	{
		in_blocks[0].iov_base = response.cur;
		in_blocks[0].iov_len = response.cur_sz;

		readv_res = readv(sock, in_blocks, 1);
		response.cur += readv_res;
		response.cur_sz -= readv_res;

		if(http_response_find_header_end(&response))
		{
			printf("Header is not found\n");
			return -5;
		}
		memcpy(request_str, response.header_end + 2,
				(response.buf_sz - response.cur_sz) -(size_t)(response.header_end - response.buf) - 2);
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
	if((response->cur = response->buf = (unsigned char*)malloc(n)) == NULL)
		return 1;

	response->cur_sz = response->buf_sz = n;
	response->header_end = NULL;

	return 0;
}

void http_response_free(HTTP_response *response)
{
	response->cur_sz = response->buf_sz = 0;
	response->header_end = NULL;
	free(response->buf);
}

int http_response_find_header_end(HTTP_response *response)
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
}



