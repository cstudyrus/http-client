#include"http-client.h"

#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<sys/socket.h>
#include<netdb.h>
#include<string.h>

ssize_t get_ipv4_address(struct in_addr*, size_t, const char*);

int main(int argc, char **argv)
{
//	char host_name[1024] = "www.google.com";
//	char host_name[1024] = "localhost";
//	char host_name[1024] = "url2cat.skydns.ru";
	char host_name[1024] = "x.api.safedns.com";
	struct in_addr addresses[16];
	ssize_t num;
	struct sockaddr_in server_addr;
	HTTP_connection conn;
	struct http_buffer *current_buffer;
	char request_str[200000] = {'\0'};
	char *request_str_p;

	int auth_need = 1;
	char auth_string[1024] = "\0";
	char cred_string[1024] = "\0";
//	char username[] = "test-url2cat-grandbase";
//	char password[] = "taG6ahTh7l";
	char username[] = "skydns";
	char password[] = "dns1356";

	HTTP_request request;
	HTTP_response response;

	num = get_ipv4_address(addresses, sizeof(addresses), host_name);


	server_addr.sin_family = AF_INET;
	server_addr.sin_addr = addresses[0];
//	server_addr.sin_port = htons(443);
//	conn = http_create_connection((const struct sockaddr*)&server_addr, HTTP_SSL_USE | HTTP_SSL_VERIFY_SERVER_CERT);
	server_addr.sin_port = htons(80);
	conn = http_create_connection((const struct sockaddr*)&server_addr, 0);

	if(conn == HTTP_CONNECTION_INVALID)
	{
		printf("Unable to create connection\n");
		return 1;
	}

	printf("Connection was established\n");

	/* //////////////// Подготовка запроса ///////////////////////////////// */
	http_request_alloc(&request, 8191);

//	http_request_set_method(&request, "GET", "1.1", "/api/v1/update/fa46ce28");
	http_request_set_method(&request, "GET", "1.1", "/domain/nytimes.com");
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

	if(http_send_request(conn, &request))
	{
		printf("Sending request error\n");
		return 1;
	}
	printf("Request was sent successfully\n");
	http_request_free(&request);


	/* /////// Получение response /////////////////// */
	http_response_alloc(&response, 8191);
	if(http_get_response(conn, &response))
	{
		printf("Response getting error\n");
		return 1;
	}
	printf("Response was obtained\n");
	/* //////////////////////////////////////////// */


	http_shutdown_connection(conn);

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

/*	int fd;

	fd = open("att.txt", O_CREAT | O_TRUNC | O_RDWR);
//	fd = open("grandbase.db", O_CREAT | O_TRUNC | O_RDWR);

	http_response_body_save(&response, fd);*/

	http_response_free(&response);

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
