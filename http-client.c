#include"http-client.h"

#include<stdlib.h>
#include<string.h>
#include<pthread.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<errno.h>

static SSL_CTX* url2cat_ctx;

struct CRYPTO_dynlock_value{
	pthread_mutex_t mtx;
};

static struct CRYPTO_dynlock_value* ssl_lock_create(const char *str, int n)
{
	struct CRYPTO_dynlock_value* result;

	result = (struct CRYPTO_dynlock_value*)malloc(sizeof(struct CRYPTO_dynlock_value));

	if(result != NULL)
		pthread_mutex_init(&result->mtx, NULL);

	return result;
}

static void ssl_lock_destroy(struct CRYPTO_dynlock_value *dnl, const char *str, int n)
{
	pthread_mutex_destroy(&dnl->mtx);
	free(dnl);
}

static void ssl_lock(int mode, struct CRYPTO_dynlock_value *dnl, const char *str, int n)
{
	if(mode & CRYPTO_LOCK)
		pthread_mutex_lock(&dnl->mtx);
	else
		pthread_mutex_unlock(&dnl->mtx);
}

static pthread_once_t ssl_lib_init = PTHREAD_ONCE_INIT;

static void ssl_lib_init_routine(void)
{
	SSL_library_init();
	url2cat_ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_default_verify_paths(url2cat_ctx);

	CRYPTO_set_dynlock_create_callback(ssl_lock_create);
	CRYPTO_set_dynlock_lock_callback(ssl_lock);
	CRYPTO_set_dynlock_destroy_callback(ssl_lock_destroy);
}

///////////////////////////////////////////////////////////
struct buffer_chunk_deskriptor
{
	const unsigned char *start;
	const unsigned char *end;

	// Показывает, является ли данная порция для записи последней.
	// Опредедить её по последней порции последнего chunk не представляется возможным,
	// так как реальна ситуация, когда в последнем буфере оказываются лишь финальные CRLF.
	// В этом случае последний буфер, в котором лишь "охвостья", воспринимается как буфер с пустым buffer_chunk_deskriptor,
	// и потому ошибочно записывается полностью, если нет явного признака последнего фрагмента для записи.
	int is_final;
	struct buffer_chunk_deskriptor *next;
};

static void http_buffer_free(struct http_buffer *b)
{
	const struct buffer_chunk_deskriptor *tmp = b->ch_d, *tmp2;

	while(tmp != NULL)
	{
		tmp2 = tmp->next;
		free((void*)tmp);
		tmp = tmp2;
	}

	free(b->buf);
	free(b);
}

static int buffer_chunk_deskriptor_add(struct http_buffer *b, const unsigned char *n)
{
	struct buffer_chunk_deskriptor *tmp = b->ch_d;
	struct buffer_chunk_deskriptor *new_desc = (struct buffer_chunk_deskriptor*)malloc(sizeof(struct buffer_chunk_deskriptor));
	if(new_desc == NULL)
		return 1;

	new_desc->start = n;
	new_desc->end = NULL;
	new_desc->next = NULL;
	new_desc->is_final = 0;

	if(tmp == NULL)
	{
		b->ch_d = new_desc;
		return 0;
	}

	while(tmp->next != NULL)
		tmp = tmp->next;
	tmp->next = new_desc;
	return 0;
}

static int buffer_chunk_deskriptor_set_last_end(struct http_buffer *b, const unsigned char *n, int is_final)
{
	struct buffer_chunk_deskriptor *new_desc;
	struct buffer_chunk_deskriptor *tmp = b->ch_d;

	if(tmp == NULL)
	{
		new_desc = (struct buffer_chunk_deskriptor*)malloc(sizeof(struct buffer_chunk_deskriptor));
		if(new_desc == NULL)
			return 1;

		new_desc->start = NULL;
		new_desc->end = n;
		new_desc->next = NULL;
		new_desc->is_final = is_final;

		b->ch_d = new_desc;
		return 0;
	}
	while(tmp->next != NULL)
		tmp = tmp->next;
	tmp->end = n;
	tmp->is_final = is_final;
	return 0;
}
///////////////////////////////////////////////////////////

HTTP_response_fd http_response_fd_create(int *fd)
{
	HTTP_response_fd result;

	result.fd = fd;
	pthread_mutex_init(&result.fd_mtx, NULL);
	pthread_cond_init(&result.fd_cv, NULL);

	return result;

}
void http_response_fd_destroy(HTTP_response_fd *response_fd)
{
	pthread_cond_destroy(&response_fd->fd_cv);
	pthread_mutex_destroy(&response_fd->fd_mtx);
}

//////////////////////////////////////////////////////////////
HTTP_connection http_create_connection(const struct sockaddr *addr, int flags)
{
	HTTP_connection result;
	char ip_address[256] = {'\0'};
	char address[300] = {'\0'};
	uint32_t fcntl_flags;

	pthread_once(&ssl_lib_init, ssl_lib_init_routine);

	result = (HTTP_connection)malloc(sizeof(struct __HTTP_connection));
	if(result == NULL)
		return HTTP_CONNECTION_INVALID;

	result->use_ssl = 0;

	switch(addr->sa_family){
	case AF_INET:
		result->domain = AF_INET;
		inet_ntop(AF_INET, &(((const struct sockaddr_in*)addr)->sin_addr), ip_address, sizeof(ip_address));
		snprintf(address, sizeof(address), "%s:%hu", ip_address, ntohs(((const struct sockaddr_in*)addr)->sin_port));
		break;
	case AF_INET6:
		result->domain = AF_INET6;
		inet_ntop(AF_INET6, &(((const struct sockaddr_in6*)addr)->sin6_addr), ip_address, sizeof(ip_address));
		snprintf(address, sizeof(address), "[%s]:%hu", ip_address, ntohs(((const struct sockaddr_in*)addr)->sin_port));
		break;
	}
	result->bio = BIO_new_connect(address);
	if(result->bio == NULL)
	{
		free(result);
		return HTTP_CONNECTION_INVALID;
	}

	if(BIO_do_connect(result->bio) != 1)
	{
		free(result);
		return HTTP_CONNECTION_INVALID;
	}

	if(flags & HTTP_SSL_USE)
	{
		if((result->ssl = SSL_new(url2cat_ctx)) == NULL)
		{
			BIO_free(result->bio);
			free(result);
			return HTTP_CONNECTION_INVALID;
		}
		if(flags & HTTP_SSL_VERIFY_SERVER_CERT)
			SSL_set_verify(result->ssl, SSL_VERIFY_PEER, NULL);

		SSL_set_bio(result->ssl, result->bio, result->bio);
		if((SSL_connect(result->ssl)) < 1)
		{
			SSL_clear(result->ssl);
			BIO_free(result->bio);
			free(result);
			return HTTP_CONNECTION_INVALID;
		}
		result->use_ssl = 1;
	}

	result->socket_fd = BIO_get_fd(result->bio, NULL);
	fcntl_flags = fcntl(result->socket_fd, F_GETFL, 0);
	fcntl(result->socket_fd, F_SETFL, fcntl_flags | O_NONBLOCK);

	return result;
}

void http_shutdown_connection(HTTP_connection connection)
{
	if(connection->use_ssl)
		SSL_shutdown(connection->ssl);
	BIO_free(connection->bio);
	close(connection->socket_fd);
	free(connection);
}

int http_send_request(HTTP_connection conn, const HTTP_request *request)
{
	struct iovec out_block;

	if(conn->use_ssl)
	{
		if(SSL_write(conn->ssl, request->buf, request->buf_sz - request->cur_sz) != request->buf_sz - request->cur_sz)
			return 1;
		else
			return 0;
	}
	else
	{
		out_block.iov_base = request->buf;
		out_block.iov_len = request->buf_sz - request->cur_sz;

		if(writev(conn->socket_fd, &out_block, 1) != out_block.iov_len)
			return 1;
		else
			return 0;
	}
}

int http_get_response(HTTP_connection conn, HTTP_response *response)
{
	fd_set rset;
	int readv_res;
	struct iovec in_block;
	int res;

	while(1)
	{
		if(conn->use_ssl && !SSL_pending(conn->ssl))
		{
			do{
				FD_ZERO(&rset);
				FD_SET(conn->socket_fd, &rset);
				pselect(conn->socket_fd + 1, &rset, NULL, NULL, NULL, NULL);
			}while(!FD_ISSET(conn->socket_fd, &rset));
		}

		if(conn->use_ssl)
		{
			readv_res = SSL_read(conn->ssl, response->cur_buffer->buf + (response->cur_buffer->buf_sz - response->cur_buffer_sz), response->cur_buffer_sz);
			while(readv_res < 0)
			{
				int ssl_error;
				ssl_error = SSL_get_error(conn->ssl,readv_res);
				if(ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
					readv_res = SSL_read(conn->ssl, response->cur_buffer->buf + (response->cur_buffer->buf_sz - response->cur_buffer_sz), response->cur_buffer_sz);
				else
					return 1;
			}
		}
		else
		{
			in_block.iov_base = response->cur_buffer->buf + (response->cur_buffer->buf_sz - response->cur_buffer_sz);
			in_block.iov_len = response->cur_buffer_sz;

			readv_res = readv(conn->socket_fd, &in_block, 1);
			while(readv_res < 0)
			{
				if(errno == EAGAIN || errno == EWOULDBLOCK)
					readv_res = readv(conn->socket_fd, &in_block, 1);
				else
					return 1;
			}
		}


		response->cur_buffer_sz -= readv_res;
		response->read += readv_res;

		if(!response->headers_num)
		{
			res = http_response_find_header_end(response);
			if(res < 0)
				return 1;
			else if(res == 0)
				http_response_get_code(response);
			else
				;
		}

		if(response->mode == CHUNK && response->read >= response->ch_num)
		{
			if(response->do_chunk_skip)
				http_response_chunk_shift(response);

			if(http_response_get_chunk_size(response))
			{
				if(response->cur_buffer_sz == 0)
					http_response_add_mem_block(response);
				continue;
			}
		}

		// Это ОБЯЗАТЕЛЬНО(!!!) должно быть на последнем месте.
		if(response->ch_num > response->read && response->cur_buffer_sz)
			continue;
		else if(response->ch_num > response->read)
			http_response_add_mem_block(response);
		else if(response->mode == LENGTH && response->ch_num == response->read)
			break;
		else if(response->mode == CHUNK && response->ch_num + 4 == response->read)
			break;
		else if(response->cur_buffer_sz)
			continue;
		else
			http_response_add_mem_block(response);
	}

	return 0;
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
	response->buffer->prev = NULL;
	response->buffer->ch_d = NULL;
	response->buffer->save_ready = 0;

//	response->cur_sz = response->buf_sz = n;
	response->cur_buffer_sz = n;
	response->header_end_buffer = NULL;
	response->header_end = NULL;
	response->status_line_buffer = NULL;
	response->status_line_end = NULL;
//	response->rest = -1;
	response->read = 0;
	response->content_length = 0;
	response->mode = FREE;
	response->headers_num = 0;

	response->chunk_buffer = NULL;
	response->chunk_size = -1;
	response->old_chunk_sum = 0;
	response->chunk_start = NULL;
	response->do_chunk_skip = 0;
	response->first_chunk = 1;
	response->ch_num = 0;

	return 0;
}

void http_response_free(HTTP_response *response)
{
/*	response->cur_sz = response->buf_sz = 0;
	response->header_end = NULL;
	free(response->buf);*/
/*	struct http_buffer *tmp;

	while(response->buffer != NULL)
	{
		free(response->buffer->buf);
		tmp = response->buffer;
		response->buffer = response->buffer->next;
		free(tmp);

	}*/

	struct http_buffer *tmp = response->buffer, *tmp2;
	while(tmp != NULL)
	{
		tmp2 = tmp->next;
		http_buffer_free(tmp);
		tmp = tmp2;
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

int http_response_get_code(HTTP_response *response)
{
	register unsigned char *current;
	register size_t n = 0;

	current = response->buffer->buf;

	while(*current != ' ')
		++current;
	while(*current == ' ')
		++current;
	response->code = (unsigned short)strtoul(current, NULL, 10);

	while(*current != ' ')
		++current;
	while(*current == ' ')
		++current;

	while(*current != '\r' || *(current+1) != '\n')
		response->code_text[n++] = *current++;
	response->code_text[n] = '\0';

	return 0;
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

/*int http_response_get_chunk_size(HTTP_response *response)
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
		while(1)
		{
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
					response->old_chunk_sum += response->chunk_size;

				if(http_response_get_chunk_size_load(response, index))
					return 2; // Недопустимый символ в chunk size.

				// Случай chunk size = 0.
				if(response->chunk_size == 4)
				{
//					response->mode = FREE;
//					response->rest = 0;
					response->chunk_size = 0;
					return 0;
				}

				if(response->read - response->old_chunk_sum <= response->chunk_size)
				{
					if(response->first_chunk)
					{
						// 2- CRLF, разделяющий header и тело;
						// 1 - Первый символ следующего chunk size, должен быть загружен.
						// CRLF (два) перед и после chunk data учтены в chunk_size.
						response->ch_num = http_response_get_header_size(response)+2 + response->chunk_size + 1 + index;
						response->first_chunk = 0;
					}
					else
						response->ch_num += response->chunk_size + index;

					response->chunk_size += index;
				}
				else
				{
					// Этот chunk уже полностью загружен. Переходим к следующему.
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
}*/

int http_response_get_chunk_size(HTTP_response *response)
{
	register struct http_buffer* current_buffer;
	register unsigned char *current;
	register unsigned char *prev = NULL;
	size_t num, index = 0;
	size_t rest_chunk_size;

struct http_buffer *chunk_start_buffer; // Начало CRLF chunk_size CRLF.
unsigned char *chunk_start;
struct http_buffer *chunk_end_buffer; // Начало следующего chunk, после текущего CRLF chunk_size CRLF.
unsigned char *chunk_end;


	if(response->chunk_buffer != NULL)
	{
		current_buffer = response->chunk_buffer;
		current = response->chunk_start;

//////// Вычисляем конец предыдущего chunk.
if((size_t)(current - current_buffer->buf) >= 2)
{
	// Это предыдущий chunk заканчивается в текущем буфере.
	chunk_end_buffer = current_buffer;
	chunk_end = current - 2;
}
else
{
//	CRLF chunk_size CRLF начинается в предыдущем memory_buffer!!!
// Найти его и обработать!!!
	// Это предыдущий chunk заканчивается в предыдущем буфере.
chunk_end_buffer = current_buffer->prev;
/*	chunk_end_buffer = response->header_end_buffer;
	while(chunk_end_buffer->next != current_buffer)
		chunk_end_buffer = chunk_end_buffer->next;*/
	chunk_end = (chunk_end_buffer->buf + chunk_end_buffer->buf_sz) - (size_t)(current - current_buffer->buf);

}
/////////

		num = (size_t)(current - current_buffer->buf);
		while(1)
		{
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
///////////////////
if((size_t)(current - current_buffer->buf) < current_buffer->buf_sz - 1)
{
	chunk_start_buffer = current_buffer;
	chunk_start = current + 1;
}
else
	// Особая ситуация!!!
	// chunk-size CRLF  падают на конец текущего memory_buffer!!!
	// Новый chunk начнётся в следующем buffer!!!
	// ОБРАБОТАТЬ!!!!!!!!!!!!!!!!!!!!
	;
// В новом буфере вообще ничего писать не нужно, для него chunk как бы продолжается из следующего.
///////////////////////


				if(response->chunk_size > 0)
					response->old_chunk_sum += response->chunk_size;

				if(http_response_get_chunk_size_load(response, index))
					return 2; // Недопустимый символ в chunk size.

				// Случай chunk size = 0.
				if(response->chunk_size == 4)
				{
// Записать информацию о последнем chunk.
buffer_chunk_deskriptor_set_last_end(chunk_end_buffer, chunk_end, 1);
					response->chunk_size = 0;
					return 0;
				}

// Записать информацию о конце предыдущего chunk и о начале нового.
if(!response->first_chunk)
	buffer_chunk_deskriptor_set_last_end(chunk_end_buffer, chunk_end, 0);
buffer_chunk_deskriptor_add(chunk_start_buffer, chunk_start);

				// Сдвигаем соответствующим образом response->ch_num.
				if(response->first_chunk)
				{
					// 2- CRLF, разделяющий header и тело;
					// 1 - Первый символ следующего chunk size, должен быть загружен.
					// CRLF (два) перед и после chunk data учтены в chunk_size.
					response->ch_num = http_response_get_header_size(response)+2 + response->chunk_size + 1 + index;
					response->first_chunk = 0;
				}
				else
					response->ch_num += response->chunk_size + index;


				if(response->read - response->old_chunk_sum <= response->chunk_size)
					response->chunk_size += index;
				else
				{
					// Этот chunk уже полностью загружен. Переходим к следующему.
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
//	int cl;

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
			response->content_length = strtol(tmp, NULL, 10);
//			response->rest = cl - (response->read - http_response_get_header_size(response) -2);
			response->ch_num = http_response_get_header_size(response) +2 + response->content_length;
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
	new_buffer->prev = response->cur_buffer;
	new_buffer->ch_d = NULL;
	new_buffer->save_ready = 0;

	response->cur_buffer->next = new_buffer;
	response->cur_buffer = new_buffer;
	response->cur_buffer_sz = new_buffer->buf_sz;

	return 0;
}


/*void http_response_body_save(HTTP_response *response, int fd)
{
	struct http_buffer *current_buffer = response->header_end_buffer;
	struct buffer_chunk_deskriptor *desc;
	const unsigned char *cur;
	size_t size;
	size_t need_write;

	switch(response->mode){
	case CHUNK:
		while(current_buffer != NULL)
		{
			desc = current_buffer->ch_d;

			if(desc == NULL && current_buffer != response->header_end_buffer)
				write(fd, current_buffer->buf, current_buffer->buf_sz);
			else if(desc == NULL)
				;
			else
				do{
					if(desc->start != NULL)
						cur = desc->start;
					else
						cur = current_buffer->buf;

					if(desc->end != NULL)
						size = (size_t)(desc->end - cur);
					else
						size = (size_t)(current_buffer->buf + current_buffer->buf_sz - cur);

					write(fd, cur, size);

					if(desc->is_final)
						return;

					desc = desc->next;

				}while(desc != NULL);

			current_buffer = current_buffer->next;
		}
		break;

	case LENGTH:
		need_write = response->content_length;

		if((size_t)(response->header_end - response->header_end_buffer->buf) < response->header_end_buffer->buf_sz - 2)
		{
			cur = response->header_end + 2;
			size = (size_t)(response->header_end_buffer->buf + response->header_end_buffer->buf_sz - cur);
		}
		else
		{
			cur = response->header_end_buffer->next->buf + (response->header_end_buffer->buf_sz - (size_t)(response->header_end - response->header_end_buffer->buf));
			size = (size_t)(response->header_end_buffer->next->buf + response->header_end_buffer->next->buf_sz - cur);

		}

		while(1)
		{
			write(fd, cur, size);

			current_buffer = current_buffer->next;
			if(current_buffer == NULL)
				return;
			cur = current_buffer->buf;
			need_write -= size;
			size = need_write > current_buffer->buf_sz ? current_buffer->buf_sz : need_write;
		}
		break;

	default:
		break;
	}
}*/

struct response_memory_buffer_save_arg{
	HTTP_response *response;
	HTTP_response_fd *response_fd;
};

void* http_response_memory_buffer_save(void *arg)
{
	struct http_buffer *current_buffer;
	struct buffer_chunk_deskriptor *desc;
	const unsigned char *cur;
	size_t size;
	size_t need_write;
	int *fd;
	HTTP_response *response;
	int predicate;

	struct response_memory_buffer_save_arg *save_arg = (struct response_memory_buffer_save_arg*)(arg);
	response = save_arg->response;
	current_buffer = response->header_end_buffer;
	fd = save_arg->response_fd->fd;

	pthread_mutex_lock(&save_arg->response_fd->fd_mtx);
while(1){
	predicate = response->header_end == NULL ||
			(response->header_end_buffer != NULL && ((!response->header_end_buffer->save_ready && response->header_end_buffer->next == NULL) ||
														(response->header_end_buffer->next != NULL && !response->header_end_buffer->next->save_ready)));
	while(predicate)
	{
		pthread_cond_wait(&save_arg->response_fd->fd_cv, &save_arg->response_fd->fd_mtx);
printf("Signal get\n");
		predicate = response->header_end == NULL ||
					(response->header_end_buffer != NULL && ((!response->header_end_buffer->save_ready && response->header_end_buffer->next == NULL) ||
														(response->header_end_buffer->next != NULL && !response->header_end_buffer->next->save_ready)));
	}
printf("Predicate OK!\n");
	current_buffer = response->header_end_buffer->save_ready ? response->header_end_buffer : response->header_end_buffer->next;
	switch(save_arg->response->mode){
	case CHUNK:
			desc = current_buffer->ch_d;

			if(desc == NULL && current_buffer != response->header_end_buffer)
				write(*fd, current_buffer->buf, current_buffer->buf_sz);
			else if(desc == NULL)
				;
			else
				do{
					if(desc->start != NULL)
						cur = desc->start;
					else
						cur = current_buffer->buf;

					if(desc->end != NULL)
						size = (size_t)(desc->end - cur);
					else
						size = (size_t)(current_buffer->buf + current_buffer->buf_sz - cur);
write(2, cur, size);
int res;
					res = write(*fd, cur, size);
if(res != size)
{
	printf("OOPS! res: %i\n", res);
}
					if(desc->is_final)
					{
						response->header_end_buffer->next = NULL;
						http_buffer_free(current_buffer);
						pthread_mutex_unlock(&save_arg->response_fd->fd_mtx);
						return NULL;
					}

					desc = desc->next;

				}while(desc != NULL);

//			current_buffer = current_buffer->next; ????
			if(current_buffer == response->header_end_buffer)
				response->header_end_buffer->save_ready = 0;
			else
			{
				response->header_end_buffer->next = current_buffer->next;
				current_buffer->next->prev = response->header_end_buffer;
				http_buffer_free(current_buffer);
			}

		break;

	case LENGTH:
		if(current_buffer == response->header_end_buffer)
		{
			need_write = response->content_length;
			current_buffer->save_ready = 0;
			if((size_t)(response->header_end - response->header_end_buffer->buf) < response->header_end_buffer->buf_sz - 2)
			{
				cur = response->header_end + 2;
				size = (size_t)(response->header_end_buffer->buf + response->header_end_buffer->buf_sz - cur);
			}
			else
				continue;
		}
		else
		{
			cur = current_buffer->buf;
			size = need_write > current_buffer->buf_sz ? current_buffer->buf_sz : need_write;
		}

		write(*fd, cur, size);
		need_write -= size;
		if(current_buffer->next != NULL)
		{
			response->header_end_buffer->next = current_buffer->next;
			current_buffer->next->prev = response->header_end_buffer;
			http_buffer_free(current_buffer);
		}
		else
		{
			response->header_end_buffer->next = NULL;
			http_buffer_free(current_buffer);
			pthread_mutex_unlock(&save_arg->response_fd->fd_mtx);
			return NULL;
		}

		break;

	default:
		break;
	}
} // while(1)
}

int http_response_body_save(HTTP_connection conn, HTTP_response *response, HTTP_response_fd *response_fd)
{
	fd_set rset;
	int readv_res;
	struct iovec in_block;
	int res;
	pthread_t writing_thread_id;
	void *writing_thread__ret;

	struct response_memory_buffer_save_arg arg;
	arg.response = response;
	arg.response_fd = response_fd;

	pthread_create(&writing_thread_id, NULL, http_response_memory_buffer_save, &arg);

	while(1)
	{
		if((conn->use_ssl && !SSL_pending(conn->ssl)) || !conn->use_ssl)
		{
			do{
				FD_ZERO(&rset);
				FD_SET(conn->socket_fd, &rset);
				pselect(conn->socket_fd + 1, &rset, NULL, NULL, NULL, NULL);
			}while(!FD_ISSET(conn->socket_fd, &rset));
		}

		if(conn->use_ssl)
		{
			readv_res = SSL_read(conn->ssl, response->cur_buffer->buf + (response->cur_buffer->buf_sz - response->cur_buffer_sz), response->cur_buffer_sz);
			while(readv_res < 0)
			{
				int ssl_error;
				ssl_error = SSL_get_error(conn->ssl,readv_res);
				if(ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
					readv_res = SSL_read(conn->ssl, response->cur_buffer->buf + (response->cur_buffer->buf_sz - response->cur_buffer_sz), response->cur_buffer_sz);
				else
				{
					pthread_cancel(writing_thread_id);
					pthread_join(writing_thread_id, &writing_thread__ret);
					return 1;
				}
			}
		}
		else
		{
			in_block.iov_base = response->cur_buffer->buf + (response->cur_buffer->buf_sz - response->cur_buffer_sz);
			in_block.iov_len = response->cur_buffer_sz;

			readv_res = readv(conn->socket_fd, &in_block, 1);
			while(readv_res < 0)
			{
				if(errno == EAGAIN || errno == EWOULDBLOCK)
					readv_res = readv(conn->socket_fd, &in_block, 1);
				else
				{
					pthread_cancel(writing_thread_id);
					pthread_join(writing_thread_id, &writing_thread__ret);
					return 1;
				}
			}
		}


		response->cur_buffer_sz -= readv_res;
		response->read += readv_res;

		if(!response->headers_num)
		{
			res = http_response_find_header_end(response);
			if(res < 0)
			{
				pthread_cancel(writing_thread_id);
				pthread_join(writing_thread_id, &writing_thread__ret);
				return 1;
			}
			else if(res == 0)
			{
				pthread_mutex_lock(&response_fd->fd_mtx);
				response->header_end_buffer->save_ready = 1;
				pthread_mutex_unlock(&response_fd->fd_mtx);
				http_response_get_code(response);
			}
			else
				;
		}

		if(response->mode == CHUNK && response->read >= response->ch_num)
		{
			if(response->do_chunk_skip)
				http_response_chunk_shift(response);

			if(http_response_get_chunk_size(response))
			{
				if(response->cur_buffer_sz == 0)
				{
					pthread_mutex_lock(&response_fd->fd_mtx);
					http_response_add_mem_block(response);
					if(response->cur_buffer->prev->prev != NULL && response->cur_buffer->prev->prev != response->header_end_buffer)
						response->cur_buffer->prev->prev->save_ready = 1;
					pthread_mutex_unlock(&response_fd->fd_mtx);
	pthread_cond_signal(&response_fd->fd_cv);
printf("1\n");
				}
				continue;
			}
		}

		// Это ОБЯЗАТЕЛЬНО(!!!) должно быть на последнем месте.
		if(response->ch_num > response->read && response->cur_buffer_sz)
			continue;
		else if(response->ch_num > response->read)
		{
			pthread_mutex_lock(&response_fd->fd_mtx);
			http_response_add_mem_block(response);
			if(response->mode == CHUNK && response->cur_buffer->prev->prev != NULL
					&& response->cur_buffer->prev->prev != response->header_end_buffer)
				response->cur_buffer->prev->prev->save_ready = 1;
			else if(response->mode == LENGTH && response->cur_buffer->prev != NULL
					&& response->cur_buffer->prev != response->header_end_buffer)
				response->cur_buffer->prev->save_ready = 1;
			else
				;
			pthread_mutex_unlock(&response_fd->fd_mtx);
	pthread_cond_signal(&response_fd->fd_cv);
printf("2\n");
		}
		else if(response->mode == LENGTH && response->ch_num == response->read)
			break;
		else if(response->mode == CHUNK && response->ch_num + 4 == response->read)
			break;
		else if(response->cur_buffer_sz)
			continue;
		else
		{
			pthread_mutex_lock(&response_fd->fd_mtx);
			http_response_add_mem_block(response);
			if(response->mode == CHUNK && response->cur_buffer->prev->prev != NULL
					&& response->cur_buffer->prev->prev != response->header_end_buffer)
				response->cur_buffer->prev->prev->save_ready = 1;
			else if(response->mode == LENGTH && response->cur_buffer->prev != NULL
					&& response->cur_buffer->prev != response->header_end_buffer)
				response->cur_buffer->prev->save_ready = 1;
			else
				;
			pthread_mutex_unlock(&response_fd->fd_mtx);
pthread_cond_signal(&response_fd->fd_cv);
printf("3\n");
		}
	}


printf("4\n");
if(response->mode == CHUNK)
{
	response->cur_buffer->save_ready = 1;
	if(response->cur_buffer->prev != NULL)
		response->cur_buffer->prev->save_ready = 1;
}
printf("Response function ended\n");
pthread_cond_signal(&response_fd->fd_cv);
	pthread_join(writing_thread_id, &writing_thread__ret);
printf("1\n");
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
