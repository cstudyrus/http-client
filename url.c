#include"url.h"

#include<ctype.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include<stdio.h>


int url_decode_char(const char *str_in)
{
	char str[4] = {'\0'};
	register int first, second;

	str[0] = str_in[0];
	str[1] = tolower(str_in[1]);
	str[2] = tolower(str_in[2]);

	if(str[0] != '%')
		return -1;

	if(str[1] >= '0' && str[1] <= '9')
		first = str[1] - '0';
	else if(str[1] >= 'a' && str[1] <= 'f')
		first = str[1] - 'a' + 10;
	else
		return -1;

	if(str[2] >= '0' && str[2] <= '9')
		second = str[2] - '0';
	else if(str[2] >= 'a' && str[2] <= 'f')
		second = str[2] - 'a' + 10;
	else
		return -1;

	return (first << 4) + second;

}

char* url_encode_char(char *res, unsigned int n)
{
	unsigned char src = (unsigned char)n;

	register unsigned char first, second;

	second = src & 0x0F;
	first = (src >> 4) & 0x0F;

	res[0] = '%';
	res[1] = first <= 9 ? first + '0' : first - 10 + 'A';
	res[2] = second <= 9 ? second + '0' : second - 10 + 'A';

	return res;
}

size_t url_count_to_encode(const char *str)
{
	register size_t result = 0;

	while(*str)
	{
		if(*str <= 32 || *str >= 127 || *str == '#' || *str == '%')
			++result;
		++str;
	}

	return result;
}

size_t url_count_to_decode(const char *str)
{
	register size_t result = 0;

	while(*str)
	{
		if(*str == '%' && isxdigit(str[1]) && isxdigit(str[2]))
			++result;
		++str;
	}

	return result;
}

ssize_t url_decode(char *dst, size_t n, const char *src)
{
	const char *cur = src;
	ssize_t sym_num = 0;
	int decode_res;

	while(*cur)
	{
		if(sym_num == n - 1)
			return ERROR_BUFFER_OVERFLOW;

		if(*cur == '%' && isxdigit(cur[1]) && isxdigit(cur[2]))
		{
			if((decode_res = url_decode_char(cur)) < 0)
				return -1;
			*dst++ = (unsigned char)(decode_res);
			cur += 3;
		}
		else
			*dst++ = *cur++;

		++sym_num;
	}
	*dst = '\0';

	return sym_num;
}

ssize_t url_encode(char *dst, size_t n, const char *src)
{
	char enc[4];
	const char *cur = src;
	ssize_t sym_num = 0;

	while(*cur)
	{
		if(*cur <= 32 || *cur >= 127 || *cur == '#' || *cur == '%')
		{
			if(sym_num + 3 >= n)
				return ERROR_BUFFER_OVERFLOW;

			url_encode_char(enc, *cur);
			*dst++ = enc[0];
			*dst++ = enc[1];
			*dst++ = enc[2];

			++cur;
			sym_num += 3;
		}
		else
		{
			if(sym_num == n - 1)
				return ERROR_BUFFER_OVERFLOW;
			*dst++ = *cur++;
			++sym_num;
		}
	}

	*dst = '\0';

	return sym_num;
}


ssize_t url_get_scheme(char *res, size_t n, const char *src)
{
	const char *scheme_end;
	ssize_t sym_num;

	if(!n)
		return ERROR_BUFFER_OVERFLOW;

	if((scheme_end = strchr(src, ':')) == NULL)
	{
		res[0] = '\0';
		return 0;
	}

	sym_num = (ssize_t)(scheme_end - src);
	if(n < sym_num + 1)
		return ERROR_BUFFER_OVERFLOW;

	strncpy(res, src, sym_num);
	res[sym_num] = '\0';

	return sym_num;
}

ssize_t url_set_scheme(char *dst, size_t n, const char *src, const char *scheme, unsigned int flags)
{
	char *scheme_end;
	ssize_t result;
	size_t scheme_len, src_len;

	scheme_len = scheme != NULL ? strlen(scheme) : 0;
	src_len = src != NULL ? strlen(src) : 0;

	// Пустой исходный URL. Создаём заготовку для нового, записывая в буфер dst  одну только схему.
	if((src == NULL || strlen(src) == 0) && (flags & NOT_USE_AUTHORITY))
	{
		if(n < scheme_len + 2)
			return ERROR_BUFFER_OVERFLOW;

		strcpy(dst, scheme);
		strcat(dst, ":");

		return (ssize_t)(scheme_len + 1);
	}
	else if(src == NULL || strlen(src) == 0)
	{
		if(n < scheme_len + 4)
			return ERROR_BUFFER_OVERFLOW;

		strcpy(dst, scheme);
		strcat(dst, "://");

		return (ssize_t)(scheme_len + 3);
	}
	else
		;


	// Ищем, есть ли схема в исхождном URL.
	if((scheme_end = strstr(src, ":")) == NULL)
	{ // В исходном URL схемы нет.
		if(scheme_len && (flags & NOT_USE_AUTHORITY))
		{ // Новая схема задана. Добавляем её в результирующий URL, НЕ используя AUTHORITY.
			if(n < scheme_len + 1 + src_len + 1)
				return ERROR_BUFFER_OVERFLOW;

			strcpy(dst, scheme);
			strcat(dst, ":");
			strcat(dst, src);

			result = (ssize_t)(scheme_len + 3 + src_len);
		}
		else if(scheme_len)
		{ // Новая схема задана. Добавляем её в результирующий URL, используя AUTHORITY.
			if(n < scheme_len + 3 + src_len + 1)
				return ERROR_BUFFER_OVERFLOW;

			strcpy(dst, scheme);
			strcat(dst, "://");
			strcat(dst, src);

			result = (ssize_t)(scheme_len + 3 + src_len);
		}
		else
		{ // Новая схема НЕ задана. Просто копируем исходный URL в результат и шабаш.
			if(n < src_len + 1)
				return ERROR_BUFFER_OVERFLOW;

			strcpy(dst, src);
			result = (ssize_t)(src_len);

			return result;
		}
	}
	else if(scheme != NULL && scheme_len)
	{ // В исходном URL есть схема и задана новая схема.
	  // Меняем схему в результирующем URL.
		if(n < scheme_len + strlen(scheme_end) +1)
			return ERROR_BUFFER_OVERFLOW;

		strcpy(dst, scheme);
		strcat(dst, scheme_end);

		result = scheme_len + strlen(scheme_end);
	}
	else
	{ // В исходном URL есть схема, но новая схема НЕ задана.
	  // Удаляем схему из исходного URL.
		if(n < strlen(scheme_end) - 2)
			return ERROR_BUFFER_OVERFLOW;

		strcpy(dst, scheme_end + 3);

		result = strlen(scheme_end) - 3;
	}

	return result;

}

size_t url_get_host_size(const char *src)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	const char *start_authority; 	// Pointer to authoriry (RFC 3986) begin in URL;
	const char *start_host; 		// Pointer to host (RFC 3986) begin in URL;
	const char *end_host;			// Pointer to host (RFC 3986) AFTER last character in URL;
	const char *end_authority;		// Pointer to authoriry (RFC 3986) AFTER last character in URL;
	const char *start_port;			// Pointer to port (RFC 3986) begin in URL;
	const char *start_path; 		// Pointer to path (RFC 3986) begin in URL;
	const char *start_post_path;	// Pointer to first character AFTER path (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;

	if(strstr(src, "://") == NULL && (start_port = strchr(src, ':')) != NULL && !isdigit(*(start_port+1)) )
	{ // Это значит, что в URL нет "://", но есть ":", за которым идёт НЕ цифра,
	  // то есть двоеточие - это НЕ порт. URL имеет вид: mailto:JoeDoe@example.com.
	  // Это значит, что имени хоста в нём нет вообще.
		return 0;
	}

	start_authority = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_port = strchr(start_authority, ':');
	start_path = strchr(start_authority, '/');
	start_query = strchr(start_authority, '?');

	// Если нет query, но есть fragment, то имя хоста или путь, если он есть,
	// заканчивается на ? или #, что раньше случится.
	if(start_query != NULL)
		start_post_path = start_query;
	else
		start_post_path = NULL;


	if(start_path == NULL && start_post_path == NULL)
		end_authority = src + strlen(src);
	else if(start_path != NULL && start_post_path == NULL)
		end_authority = start_path;
	else if(start_path == NULL && start_post_path != NULL)
		end_authority = start_post_path;
	else if(start_path < start_post_path)
		end_authority = start_path;
	else
		end_authority = start_post_path;

	// Если в URL есть User Name, то оно заканчивается на @.
	start_host = strchr(start_authority, '@');
	if(start_host == NULL || start_host > end_authority)
		start_host = start_authority;
	else
		++start_host;

	// Если в URL есть порт, то имя хоста завершается на :.
	end_host = (start_port != NULL && start_port < end_authority) ? start_port : end_authority;

	return (size_t)(end_host - start_host);

}

ssize_t url_get_host(char *dst, size_t n, const char *src)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	const char *start_authority; 	// Pointer to authoriry (RFC 3986) begin in URL;
	const char *start_host; 		// Pointer to host (RFC 3986) begin in URL;
	const char *end_host;			// Pointer to host (RFC 3986) AFTER last character in URL;
	const char *end_authority;		// Pointer to authoriry (RFC 3986) AFTER last character in URL;
	const char *start_port;			// Pointer to port (RFC 3986) begin in URL;
	const char *start_path; 		// Pointer to path (RFC 3986) begin in URL;
	const char *start_post_path;	// Pointer to first character AFTER path (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;

	size_t sym_num = 0;

	if(strstr(src, "://") == NULL && (start_port = strchr(src, ':')) != NULL && !isdigit(*(start_port+1)) )
	{ // Это значит, что в URL нет "://", но есть ":", за которым идёт НЕ цифра,
	  // то есть двоеточие - это НЕ порт. URL имеет вид: mailto:JoeDoe@example.com.
	  // Это значит, что имени хоста в нём нет вообще.
		dst[0] = '\0';
		return 0;
	}

	start_authority = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_port = strchr(start_authority, ':');
	start_path = strchr(start_authority, '/');
	start_query = strchr(start_authority, '?');

	// Если нет query, но есть fragment, то имя хоста или путь, если он есть,
	// заканчивается на ? или #, что раньше случится.
	if(start_query != NULL)
		start_post_path = start_query;
	else
		start_post_path = NULL;


	if(start_path == NULL && start_post_path == NULL)
		end_authority = src + strlen(src);
	else if(start_path != NULL && start_post_path == NULL)
		end_authority = start_path;
	else if(start_path == NULL && start_post_path != NULL)
		end_authority = start_post_path;
	else if(start_path < start_post_path)
		end_authority = start_path;
	else
		end_authority = start_post_path;

	// Если в URL есть User Name, то оно заканчивается на @.
	start_host = strchr(start_authority, '@');
	if(start_host == NULL || start_host > end_authority)
		start_host = start_authority;
	else
		++start_host;

	// Если в URL есть порт, то имя хоста завершается на :.
	end_host = (start_port != NULL && start_port < end_authority) ? start_port : end_authority;

	sym_num = (size_t)(end_host - start_host);
	if(n < sym_num + 1)
		return ERROR_BUFFER_OVERFLOW;

	strncpy(dst, start_host, sym_num);
	dst[sym_num] = '\0';

	return (ssize_t)sym_num;
}

ssize_t url_set_host(char *dst, size_t n, const char *src, const char *host)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	const char *start_authority; 	// Pointer to authoriry (RFC 3986) begin in URL;
	const char *start_host; 		// Pointer to host (RFC 3986) begin in URL;
	const char *end_host;			// Pointer to host (RFC 3986) AFTER last character in URL;
	const char *end_authority;		// Pointer to authoriry (RFC 3986) AFTER last character in URL;
	const char *start_port;			// Pointer to port (RFC 3986) begin in URL;
	const char *start_path; 		// Pointer to path (RFC 3986) begin in URL;
	const char *start_post_path;	// Pointer to first character AFTER path (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;

	size_t username_size = 0;
	size_t sym_num = 0;
	ssize_t result;

	start_authority = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_port = strchr(start_authority, ':');
	start_path = strchr(start_authority, '/');
	start_query = strchr(start_authority, '?');

	// Если нет query, но есть fragment, то имя хоста или путь, если он есть,
		// заканчивается на ? или #, что раньше случится.
	if(start_query != NULL)
		start_post_path = start_query;
	else
		start_post_path = NULL;

	if(start_path == NULL && start_post_path == NULL)
		end_authority = src + strlen(src);
	else if(start_path != NULL && start_post_path == NULL)
		end_authority = start_path;
	else if(start_path == NULL && start_post_path != NULL)
		end_authority = start_post_path;
	else if(start_path < start_post_path)
		end_authority = start_path;
	else
		end_authority = start_post_path;

	// Если в URL есть User Name, то оно заканчивается на @.
	start_host = strchr(start_authority, '@');
	if(start_host == NULL || start_host > end_authority)
		start_host = start_authority;
	else
	{
		++start_host;
		username_size = (size_t)(start_host - start_authority);
	}

	// Если в URL есть порт, то имя хоста завершается на :.
	end_host = (start_port != NULL && start_port < end_authority) ? start_port : end_authority;

	if((result = url_get_scheme(dst, n, src)) < 0)
		return result;
	sym_num =  3 + username_size +strlen(host) + strlen(end_host);
	if(n < result + sym_num + 1)
		return ERROR_BUFFER_OVERFLOW;

	if(result)
		strcat(dst, "://");
	if(username_size)
		strncat(dst, start_authority, username_size);
	strcat(dst, host);
	strcat(dst, end_host);

	result += sym_num;

	return result;
}

size_t url_get_path_size(const char *src)
{
	const char *start_host = NULL;
	const char *scheme_end = NULL;
	const char *start_path = NULL;
	const char *end_path = NULL;
	const char *start_query = NULL;

	start_host = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_path = strchr(start_host, '/');
	start_query = strchr(start_host, '?');
	if(start_path == NULL || (start_query && start_query < start_path))
		return 0;

	if(start_query == NULL)
		end_path = src + strlen(src);
	else
		end_path = start_query;

	return  (size_t)(end_path - start_path);
}

ssize_t url_get_path(char *dst, size_t n, const char *src)
{
	const char *start_host;
	const char *scheme_end, *start_path, *end_path, *start_query;
	size_t sym_num = 0;

	if(!n)
		return ERROR_BUFFER_OVERFLOW;

	start_host = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_path = strchr(start_host, '/');
	start_query = strchr(start_host, '?');
	if(start_path == NULL || (start_query && start_query < start_path))
	{
		dst[0] = '\0';
		return 0;
	}

	if(start_query == NULL)
		end_path = src + strlen(src);
	else
		end_path = start_query;

	sym_num = (size_t)(end_path - start_path);
	if(n < sym_num + 1)
		return ERROR_BUFFER_OVERFLOW;
	strncpy(dst, start_path, sym_num);
	dst[sym_num] = '\0';

	return (ssize_t)sym_num;
}

ssize_t url_set_path(char *dst, size_t n, const char *src, const char *path)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	const char *start_authority; 	// Pointer to authoriry (RFC 3986) begin in URL;
	const char *start_path; 		// Pointer to path (RFC 3986) begin in URL;
	const char *start_post_path;	// Pointer to first character AFTER path (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;
	const char *src_end;

	size_t sym_num = 0, sym_num_2 = 0;

	start_authority = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_path = strchr(start_authority, '/');
	start_query = strchr(start_authority, '?');


	src_end = src + strlen(src);
	if(start_query != NULL)
		start_post_path = start_query;
	else
		start_post_path = src_end;

	if(start_path == NULL)
		start_path = start_post_path;

	sym_num_2 = (size_t)(start_path - src);
	sym_num = (path[0] == '/') ? sym_num_2 + strlen(path) + (size_t)(src_end - start_post_path) :
				sym_num_2 + 1 +strlen(path) + (size_t)(src_end - start_post_path);
	if(n < sym_num + 1)
		return ERROR_BUFFER_OVERFLOW;

	strncpy(dst, src, sym_num_2);
	if(path[0] != '/')
		dst[sym_num_2++] = '/';
	dst[sym_num_2] = '\0';
	strcat(dst, path);
	strcat(dst, start_post_path);

	return sym_num;
}


unsigned short url_get_port(const char* src)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	const char *start_authority; 	// Pointer to authoriry (RFC 3986) begin in URL;
	const char *end_authority;		// Pointer to authoriry (RFC 3986) AFTER last character in URL;
	const char *start_port;			// Pointer to port (RFC 3986) begin in URL;
	const char *start_path; 		// Pointer to path (RFC 3986) begin in URL;
	const char *start_post_path;	// Pointer to first character AFTER path (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;

	size_t sym_num = 0;
	char port_str[6] = {'\0'};

	if(strstr(src, "://") == NULL && (start_port = strchr(src, ':')) != NULL && !isdigit(*(start_port+1)) )
	{ // Это значит, что в URL нет "://", но есть ":", за которым идёт НЕ цифра,
	 // то есть двоеточие - это НЕ порт. URL имеет вид: mailto:JoeDoe@example.com.
	//	Это значит, что порта в нём не может быть вообще.
		return 0;
	}

	start_authority = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_port = strchr(start_authority, ':');
	start_path = strchr(start_authority, '/');
	start_query = strchr(start_authority, '?');

	// Если нет query, но есть fragment, то имя хоста или путь, если он есть,
	// заканчивается на ? или #, что раньше случится.
	if(start_query != NULL)
		start_post_path = start_query;
	else
		start_post_path = NULL;

	if(start_port == NULL || (start_post_path != NULL && start_port > start_post_path))
		return 0; // Эьл значит, что порта в URL нет.

	if(start_path == NULL && start_post_path == NULL)
		end_authority = src + strlen(src);
	else if(start_path != NULL && start_post_path == NULL)
		end_authority = start_path;
	else if(start_path == NULL && start_post_path != NULL)
		end_authority = start_post_path;
	else if(start_path < start_post_path)
		end_authority = start_path;
	else
		end_authority = start_post_path;

	sym_num = end_authority - start_port - 1;
	strncpy(port_str, start_port + 1, sym_num);

	return (unsigned short)strtoul(port_str, NULL, 10);
}

ssize_t url_set_port(char* dst, size_t n, const char* src, unsigned short port)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	const char *start_authority; 	// Pointer to authoriry (RFC 3986) begin in URL;
	const char *end_authority;		// Pointer to authoriry (RFC 3986) AFTER last character in URL;
	const char *end_host;			// Pointer to host (RFC 3986) AFTER last character in URL;
	const char *start_port;			// Pointer to port (RFC 3986) begin in URL;
	const char *start_path; 		// Pointer to path (RFC 3986) begin in URL;
	const char *start_post_path;	// Pointer to first character AFTER path (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;

	size_t sym_num = 0, sym_num_2 = 0;
	char port_str[7] = {'\0'};

	if(port == 0)
		return ERROR_INCORRECT_PORT;

	if(strstr(src, "://") == NULL && (start_port = strchr(src, ':')) != NULL && !isdigit(*(start_port+1)) )
	{ // Это значит, что в URL нет "://", но есть ":", за которым идёт НЕ цифра,
	 // то есть двоеточие - это НЕ порт. URL имеет вид: mailto:JoeDoe@example.com.
	 // Это значит, что порта в нём не может быть вообще.
		return 0;
	}

	start_authority = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_port = strchr(start_authority, ':');
	start_path = strchr(start_authority, '/');
	start_query = strchr(start_authority, '?');

	// Если нет query, но есть fragment, то имя хоста или путь, если он есть,
	// заканчивается на ? или #, что раньше случится.
	if(start_query != NULL)
		start_post_path = start_query;
	else
		start_post_path = NULL;

	if(start_path == NULL && start_post_path == NULL)
		end_authority = src + strlen(src);
	else if(start_path != NULL && start_post_path == NULL)
		end_authority = start_path;
	else if(start_path == NULL && start_post_path != NULL)
		end_authority = start_post_path;
	else if(start_path < start_post_path)
		end_authority = start_path;
	else
		end_authority = start_post_path;

	// Если в URL есть порт, то имя хоста завершается на :.
	end_host = (start_port != NULL && start_port < end_authority) ? start_port : end_authority;

	snprintf(port_str, 7, ":%hu", port);

	sym_num_2 = (size_t)(end_host - src);
	sym_num = sym_num_2 + strlen(port_str) + strlen(end_authority);
	if(n < sym_num + 1)
		return ERROR_BUFFER_OVERFLOW;

	strncpy(dst, src, sym_num_2);
	dst[sym_num_2] = '\0';
	strcat(dst, port_str);
	strcat(dst, end_authority);

	return sym_num;
}

char* url_remove_port(char* src)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	const char *start_authority; 	// Pointer to authoriry (RFC 3986) begin in URL;
	const char *end_authority;		// Pointer to authoriry (RFC 3986) AFTER last character in URL;
	char *start_port;			// Pointer to port (RFC 3986) begin in URL;
	const char *start_path; 		// Pointer to path (RFC 3986) begin in URL;
	const char *start_post_path;	// Pointer to first character AFTER path (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;

	size_t sym_num = 0;

	if(strstr(src, "://") == NULL && (start_port = strchr(src, ':')) != NULL && !isdigit(*(start_port+1)) )
	{ // Это значит, что в URL нет "://", но есть ":", за которым идёт НЕ цифра,
	 // то есть двоеточие - это НЕ порт. URL имеет вид: mailto:JoeDoe@example.com.
	//	Это значит, что порта в нём не может быть вообще.
		return src;
	}

	start_authority = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_port = strchr(start_authority, ':');
	start_path = strchr(start_authority, '/');
	start_query = strchr(start_authority, '?');

	// Если нет query, но есть fragment, то имя хоста или путь, если он есть,
	// заканчивается на ? или #, что раньше случится.
	if(start_query != NULL)
		start_post_path = start_query;
	else
		start_post_path = NULL;

	if(start_port == NULL || (start_post_path != NULL && start_port > start_post_path))
		return src; // Это значит, что порта в URL нет.

	if(start_path == NULL && start_post_path == NULL)
		end_authority = src + strlen(src);
	else if(start_path != NULL && start_post_path == NULL)
		end_authority = start_path;
	else if(start_path == NULL && start_post_path != NULL)
		end_authority = start_post_path;
	else if(start_path < start_post_path)
		end_authority = start_path;
	else
		end_authority = start_post_path;

	if(end_authority != NULL)
	{
		sym_num = 0;
		while(end_authority[sym_num + 1])
		{
			start_port[sym_num] = end_authority[sym_num];
			++sym_num;
		}
		start_port[sym_num] = '\0';
	}
	else
		start_port[0] = '\0';


	return src;
}

ssize_t url_get_userinfo(char* dst, size_t n, const char* src)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	const char *start_authority; 	// Pointer to authoriry (RFC 3986) begin in URL;
	const char *start_host; 		// Pointer to host (RFC 3986) begin in URL;
	const char *end_authority;		// Pointer to authoriry (RFC 3986) AFTER last character in URL;
	const char *start_path; 		// Pointer to path (RFC 3986) begin in URL;
	const char *start_post_path;	// Pointer to first character AFTER path (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;

	size_t sym_num = 0;
	if(!n)
		return ERROR_BUFFER_OVERFLOW;

	start_authority = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_path = strchr(start_authority, '/');
	start_query = strchr(start_authority, '?');

	// Если нет query, но есть fragment, то имя хоста или путь, если он есть,
	// заканчивается на ? или #, что раньше случится.
	if(start_query != NULL)
		start_post_path = start_query;
	else
		start_post_path = NULL;


	if(start_path == NULL && start_post_path == NULL)
		end_authority = src + strlen(src);
	else if(start_path != NULL && start_post_path == NULL)
		end_authority = start_path;
	else if(start_path == NULL && start_post_path != NULL)
		end_authority = start_post_path;
	else if(start_path < start_post_path)
		end_authority = start_path;
	else
		end_authority = start_post_path;

	// Если в URL есть User Name, то оно заканчивается на @.
	start_host = strchr(start_authority, '@');
	if(start_host != NULL && start_host <= end_authority)
	{ // Это значит, что userinfo в URL есть.
		sym_num = (size_t)(start_host - start_authority);
		if(n < sym_num + 1)
			return ERROR_BUFFER_OVERFLOW;
		strncpy(dst, start_authority, sym_num);
		dst[sym_num] = '\0';

		return sym_num;
	}
	else
	{ // Это значит, что userinfo в URL нет.
		dst[0] = '\0';
		return 0;
	}

}

ssize_t url_set_userinfo(char* dst, size_t n, const char* src, const char* userinfo)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	const char *start_authority; 	// Pointer to authoriry (RFC 3986) begin in URL;
	const char *start_host; 		// Pointer to host (RFC 3986) begin in URL;
	const char *end_authority;		// Pointer to authoriry (RFC 3986) AFTER last character in URL;
	const char *start_path; 		// Pointer to path (RFC 3986) begin in URL;
	const char *start_post_path;	// Pointer to first character AFTER path (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;

	size_t sym_num = 0, sym_num_2 = 0;

	if(userinfo == NULL || userinfo[0] == '\0')
		return 0;

	start_authority = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_path = strchr(start_authority, '/');
	start_query = strchr(start_authority, '?');

	// Если нет query, но есть fragment, то имя хоста или путь, если он есть,
	// заканчивается на ? или #, что раньше случится.
	if(start_query != NULL)
		start_post_path = start_query;
	else
		start_post_path = NULL;


	if(start_path == NULL && start_post_path == NULL)
		end_authority = src + strlen(src);
	else if(start_path != NULL && start_post_path == NULL)
		end_authority = start_path;
	else if(start_path == NULL && start_post_path != NULL)
		end_authority = start_post_path;
	else if(start_path < start_post_path)
		end_authority = start_path;
	else
		end_authority = start_post_path;

	// Если в URL есть User Name, то оно заканчивается на @.
	start_host = strchr(start_authority, '@');
	if(start_host == NULL || start_host > end_authority)
		start_host = start_authority;
	else
		++start_host;


	sym_num_2 = (size_t)(start_authority - src);
	sym_num = sym_num_2 + strlen(userinfo) + 1 + strlen(start_host);
	if(n < sym_num + 1)
			return ERROR_BUFFER_OVERFLOW;

	strncpy(dst, src, sym_num_2);
	dst[sym_num_2] = '\0';
	strcat(dst, userinfo);
	strcat(dst, "@");
	strcat(dst, start_host);

	return sym_num;
}

char* url_remove_userinfo(char* src)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	char *start_authority; 			// Pointer to authoriry (RFC 3986) begin in URL;
	const char *start_host; 		// Pointer to host (RFC 3986) begin in URL;
	const char *end_authority;		// Pointer to authoriry (RFC 3986) AFTER last character in URL;
	const char *start_path; 		// Pointer to path (RFC 3986) begin in URL;
	const char *start_post_path;	// Pointer to first character AFTER path (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;

	size_t sym_num = 0;

	start_authority = (char*)(((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src);
	start_path = strchr(start_authority, '/');
	start_query = strchr(start_authority, '?');

	// Если нет query, но есть fragment, то имя хоста или путь, если он есть,
	// заканчивается на ? или #, что раньше случится.
	if(start_query != NULL)
		start_post_path = start_query;
	else
		start_post_path = NULL;


	if(start_path == NULL && start_post_path == NULL)
		end_authority = src + strlen(src);
	else if(start_path != NULL && start_post_path == NULL)
		end_authority = start_path;
	else if(start_path == NULL && start_post_path != NULL)
		end_authority = start_post_path;
	else if(start_path < start_post_path)
		end_authority = start_path;
	else
		end_authority = start_post_path;

	// Если в URL есть userinfo, то оно заканчивается на @.
	start_host = strchr(start_authority, '@');
	if(start_host != NULL && start_host <= end_authority)
	{ // Это значит, что userinfo в URL есть.
		sym_num = 0;
		while(start_host[sym_num + 1])
		{
			start_authority[sym_num] = start_host[sym_num + 1];
			++sym_num;
		}
		start_authority[sym_num] = '\0';
	}

	return src;

}

int url_get_query(url_query_params q, const char *src)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	char *start_authority; 			// Pointer to authoriry (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;
	const char *end_query;			// Pointer to first character AFTER query in URL;
	char *buf;
	size_t buf_len;
	int result;

	start_authority = (char*)(((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src);
	start_query = strchr(start_authority, '?');

	if(start_query == NULL)
	{
		url_query_params_clear(q);
		return 0;
	}
	end_query = src + strlen(src);

	buf_len = (size_t)(end_query - start_query);
	if((buf = (char*)calloc(buf_len, sizeof(char))) == NULL)
		return ERROR_MEMORY_ALLOC;
	memcpy(buf, start_query + 1, buf_len - 1);
	buf[buf_len] = '\0';

	result = url_query_params_load(q, buf);
	free(buf);

	return result;
}

ssize_t url_set_query(char* dst, size_t n, url_query_params q, const char *src)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	const char *start_authority; 	// Pointer to authoriry (RFC 3986) begin in URL;
	const char *start_query;		// Pointer to query (RFC 3986) begin in URL;
	const char *end_query;			// Pointer to first character AFTER query in URL;

	char *query_str;
	size_t query_str_len;
	size_t sym_num = 0;
	size_t prefix_len;
	int res;

	if(q->n == 0 && n == 0)
		return ERROR_BUFFER_OVERFLOW;
	else if(q->n == 0 && n < strlen(src) + 1)
		return ERROR_BUFFER_OVERFLOW;
	else if(q->n == 0)
	{
		strcpy(dst, src);
		return strlen(src);
	}

	if((query_str = (char*)calloc(n, sizeof(char))) == NULL)
		return ERROR_MEMORY_ALLOC;
	if((res = url_query_params_to_string(q, query_str, n)) < 0)
	{
		free(query_str);
		return res;
	}
	query_str_len = strlen(query_str);

	start_authority = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_query = strchr(start_authority, '?');

	// Если нет query, но есть fragment, то имя хоста или путь, если он есть,
	// заканчивается на ?.
	if(start_query == NULL)
		start_query = end_query = src + strlen(src);
	else
		end_query = src + strlen(src);

	prefix_len = (size_t)(start_query - src);
	sym_num = prefix_len + 1 + query_str_len + strlen(end_query);

	if(n < sym_num + 1)
		return ERROR_BUFFER_OVERFLOW;

	strncpy(dst, src, (size_t)(start_query - src));
	dst[prefix_len] = '?';
	dst[prefix_len + 1] = '\0';
	strcat(dst, query_str);
	strcat(dst, end_query);

	return sym_num;
}

char* url_remove_query(char *src)
{
	const char *scheme_end;			// Pointer to schema (RFC 3986) AFTER last character in URL;
	const char *start_authority; 	// Pointer to authoriry (RFC 3986) begin in URL;
	char *start_query;				// Pointer to query (RFC 3986) begin in URL;
	char *end_query;			// Pointer to first character AFTER query in URL;

	size_t sym_num = 0;

	start_authority = ((scheme_end = strstr(src, "://")) != NULL) ? scheme_end + 3 : src;
	start_query = strchr(start_authority, '?');

	// Если нет query, но есть fragment, то имя хоста или путь, если он есть,
	// заканчивается на ?.
	if(start_query == NULL)
		start_query = end_query = (char*)(src + strlen(src));
	else
		end_query = (char*)(src + strlen(src));

	while(*end_query)
		start_query[sym_num++] = *end_query++;
	start_query[sym_num] = '\0';

	return src;
}


ssize_t url_get_fragment(char* dst, size_t n, const char* src)
{
	const char *start_fragment;		// Pointer to fragment (RFC 3986) begin in URL;
	size_t fragment_length;

	if(!n)
		return ERROR_BUFFER_OVERFLOW;

	start_fragment = strchr(src, '#');

	if(start_fragment != NULL)
	{
		fragment_length = strlen(start_fragment + 1);
		if(n < fragment_length + 1)
			return ERROR_BUFFER_OVERFLOW;
		strcpy(dst, start_fragment + 1);

		return fragment_length;
	}
	else
	{
		dst[0] = '\0';
		return 0;
	}
}

char* url_remove_fragment(char *str)
{
	register char *src = str;

	while(*src)
	{
		if(*src == '#')
		{
			*src = '\0';
			break;
		}
		++src;
	}

	return str;
}






