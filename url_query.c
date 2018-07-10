#include"url_query.h"
#include"url.h"

#include<stdlib.h>
#include<string.h>

int url_query_params_init(url_query_params *q)
{
	if((*q = malloc(sizeof(struct __url_query_params))) == NULL)
		return ERROR_MEMORY_ALLOC;

	(*q)->keys = NULL;
	(*q)->values = NULL;
	(*q)->n = 0;

	return 0;
}

void url_query_params_close(url_query_params q)
{
	size_t i;

	for(i = 0; i < q->n; ++i)
	{
		free(q->keys[i]);
		free(q->values[i]);
	}
	free(q);
}

int url_query_params_load(url_query_params q, const char *src)
{
	const char *amp_poi, *start_pair = src, *eq_sign;
	const char *start_key, *end_key, *start_value, *end_value;
	size_t key_sz, value_sz, index = 0;

	url_query_params_clear(q);

	while((start_pair = strchr(start_pair, '&')) != NULL)
	{
		++q->n ;
		++start_pair;
	}
	++q->n ;
	if((q->keys = (char**)calloc(q->n, sizeof(char*))) == NULL)
	{
		q->n = 0;
		return ERROR_MEMORY_ALLOC;
	}
	if((q->values = (char**)calloc(q->n, sizeof(char*))) == NULL)
	{
		url_query_params_clear(q);
		return ERROR_MEMORY_ALLOC;
	}


	start_pair = src;
	for(index = 0; index < q->n; ++index)
	{
		amp_poi = strchr(start_pair, '&');
		if(amp_poi == NULL)
			amp_poi = src + strlen(src);

		start_key = start_pair;
		end_key = amp_poi;
		start_value = end_value =  NULL;

		eq_sign = strchr(start_key, '=');
		if(eq_sign != NULL && eq_sign < amp_poi)
		{
			end_value = end_key;
			end_key = eq_sign;
			start_value = eq_sign + 1;
		}

		key_sz = (size_t)(end_key - start_key);
		value_sz = (start_value != NULL) ? (size_t)(end_value - start_value) : 0;
		if((q->keys[index] = (char*)calloc(key_sz + 1, sizeof(char))) == NULL)
		{
			url_query_params_clear(q);
			return ERROR_MEMORY_ALLOC;
		}
		if((q->values[index] = (char*)calloc(value_sz + 1, sizeof(char))) == NULL)
		{
			url_query_params_clear(q);
			return ERROR_MEMORY_ALLOC;
		}
		memcpy(q->keys[index], start_key, key_sz);
		q->keys[index][key_sz] = '\0';
		if(value_sz)
			memcpy(q->values[index], start_value, value_sz);
		q->values[index][value_sz] = '\0';

		start_pair = amp_poi + 1;
	}

	return 0;
}

ssize_t url_query_params_to_string(url_query_params q, char *dst, size_t n)
{
	size_t i, val_length;
	size_t res_length;

	if(!n)
		return ERROR_BUFFER_OVERFLOW;

	if(q->n == 0)
	{
		dst[0] = '\0';
		return 0;
	}

	res_length = q->n - 1; // Это амперсанды.
	for(i = 0; i < q->n; ++i)
	{
		res_length += strlen(q->keys[i]);
		val_length = strlen(q->values[i]);
		if(val_length)
			res_length += val_length + 1; // Учтён =

	}

	if(n <= val_length + 1)
		return ERROR_BUFFER_OVERFLOW;

	dst[0] = '\0';
	for(i = 0; i < q->n; ++i)
	{
		if(i)
			strcat(dst,"&");
		strcat(dst, q->keys[i]);
		if(q->values[i][0])
		{
			strcat(dst, "=");
			strcat(dst, q->values[i]);
		}
	}

	return res_length;
}

int url_query_params_get_value(url_query_params q, char *dst, size_t n, const char *key)
{
	size_t i;

	for(i = 0; i < q->n; ++i)
		if(!strcmp(q->keys[i], key))
		{
			if(n < strlen(q->values[i]) + 1)
				return ERROR_BUFFER_OVERFLOW;
			strcpy(dst, q->values[i]);
			return 0;
		}

	return ERROR_NO_SUCH_KEY;
}

int url_query_params_set_value(url_query_params q, const char *key, const char *value)
{
	size_t i, value_length;
	char *tmp;

	for(i = 0; i < q->n; ++i)
		if(!strcmp(q->keys[i], key))
		{
			value_length = strlen(value);
			if(strlen(q->values[i]) != value_length)
			{
				if((tmp = (char*)realloc(q->values[i], value_length)) == NULL)
					return ERROR_MEMORY_ALLOC;

				q->values[i] = tmp;
				strcpy(q->values[i], value);
			}
			return 0;
		}

	return ERROR_NO_SUCH_KEY;
}

int url_query_params_remove_key(url_query_params q, const char *key)
{
	size_t i,j;

	for(i = 0; i < q->n; ++i)
		if(!strcmp(q->keys[i], key))
		{
			free(q->keys[i]);
			free(q->values[i]);

			for(j = i+1; j < q->n; ++j)
			{
				q->keys[j-1] = q->keys[j];
				q->values[j-1] = q->values[j];
			}

			q->keys = (char**)realloc(q->keys, q->n - 1);
			q->values = (char**)realloc(q->values, q->n - 1);

			--q->n;
			return 0;
		}

	return ERROR_NO_SUCH_KEY;
}

int url_query_params_add_key(url_query_params q, const char *key, const char *value)
{
	char **tmp1, **tmp2;
	char *tmp3, *tmp4;
	size_t i, value_sz;

	if(key == NULL || key[0] == '\0')
		return 0;

	for(i = 0; i < q->n; ++i)
		if(!strcmp(q->keys[i],  key))
			return ERROR_KEY_ALREADY_EXIST;

	if((tmp1 = (char**)realloc(q->keys, q->n + 1)) == NULL)
		return ERROR_MEMORY_ALLOC;

	if((tmp2 = (char**)realloc(q->values, q->n + 1)) == NULL)
	{
			q->keys = (char**)realloc(tmp1, q->n);
			return ERROR_MEMORY_ALLOC;
	}

	if((tmp3 = (char*)calloc(strlen(key) + 1, sizeof(char))) == NULL)
	{
		q->values = (char**)realloc(q->values, q->n);
		q->keys = (char**)realloc(q->keys, q->n);
		return ERROR_MEMORY_ALLOC;
	}

	value_sz = value != NULL ? strlen(value) + 1 : 1;
	if((tmp4 = (char*)calloc(value_sz, sizeof(char))) == NULL)
	{
		free(tmp3);
		q->values = (char**)realloc(tmp2, q->n);
		q->keys = (char**)realloc(tmp1, q->n);
		return ERROR_MEMORY_ALLOC;
	}

	q->keys = tmp1;
	q->values = tmp2;
	q->keys[q->n] = tmp3;
	q->values[q->n] = tmp4;
	strcpy(q->keys[q->n], key);
	if(value != NULL)
		strcpy(q->values[q->n], value);
	else
		q->values[q->n][0] = '\0';
	++q->n;

	return 0;
}

ssize_t url_query_params_get_key_index(url_query_params q, const char *key)
{
	size_t i;

	for(i = 0; i < q->n; ++i)
		if(!strcmp(q->keys[i], key))
			return (ssize_t)(i);

	return ERROR_NO_SUCH_KEY;
}

int url_query_params_set_key_index(url_query_params q, const char *key, size_t index)
{
	size_t old_index;
	size_t i;
	char *tmp_key, *tmp_val;

	if( index >= q->n)
		return ERROR_NO_SUCH_KEY_INDEX;


	for(i = 0; i < q->n; ++i)
		if(!strcmp(q->keys[i], key))
		{
			old_index = i;
			break;
		}

	if(i == q->n)
		return ERROR_NO_SUCH_KEY;

	if(old_index < index)
	{
		tmp_key = q->keys[old_index];
		tmp_val = q->values[old_index];
		for(i = old_index; i < index; ++i)
		{
			q->keys[i] = q->keys[i+1];
			q->values[i] = q->values[i+1];
		}
		q->keys[index] = tmp_key;
		q->values[index] = tmp_val;

		return 0;
	}
	else if(old_index > index)
	{
		tmp_key = q->keys[old_index];
		tmp_val = q->values[old_index];
		for(i = old_index; i > index; --i)
		{
			q->keys[i] = q->keys[i-1];
			q->values[i] = q->values[i-1];
		}
		q->keys[index] = tmp_key;
		q->values[index] = tmp_val;

		return 0;
	}
	else
		return 0;

}


void url_query_params_clear(url_query_params q)
{
	size_t i;

	for(i = 0; i < q->n; ++i)
	{
		free(q->keys[i]);
		free(q->values[i]);
	}

	q->n = 0;
}



