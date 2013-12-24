/* l7fsm http parser module
 * Copyright (c) 2013 by Ilya Gavrilov <gilyav@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

%%{
	machine l7fsm_http;

	action got_method
	{
		L7NFDEBUG("got http method\n");
	}

	action got_url
	{
		L7NFDEBUG("got http url\n");
	}

	action got_http_request
	{
		L7NFDEBUG("got http request\n");
		return 1;
	}

	action got_version
	{
		L7NFDEBUG("got http version\n");
	}

	action got_http_response
	{
		L7NFDEBUG("got http response\n");
		return 1;
	}

	method = ('GET'i | 'POST'i | 'CONNECT'i | 'HEAD'i | 'DELETE'i | 'LINK'i | 
			  'PUT'i | 'PATCH'i | 'UNLINK'i | 'TRACE'i) %got_method;
	url = ( [^ ]+ ) %got_url;
	http_version =  'HTTP/'i digit {1,2} '.' digit {1,2} %got_version;

	http_request = ( method . [ \t]+ . url . [ \t]+ . http_version . '\r'? '\n' ) @got_http_request;
	http_response = http_version . [ \t]+ . digit+ . [^\r\n]* . '\r'? '\n' @got_http_response;

	http_filter = http_request | http_response;

	main := http_filter;
}%%

%% write data;

void l7fsm_http_init(int *state)
{
	int cs = *state;
	%% write init;
	*state = cs;
}

int l7fsm_http_parse( int *state, const char *data, int len, int isEof )
{
	const char *p = data;
	const char *pe = data + len;

	int cs = *state;
	%% write exec;

	*state = cs;
	if ( cs == l7fsm_http_error )
		return -1;
	if ( cs >= l7fsm_http_first_final )
		return 1;
	return 0;
}

