/* l7fsm sip parser  module
 * Copyright (c) 2013 by Ilya Gavrilov <gilyav@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

%%{
	machine l7fsm_sip;

	action got_method
	{
		L7NFDEBUG("got sip method\n");
	}

	action got_url
	{
		L7NFDEBUG("got sip url\n");
	}

	action got_sip_request
	{
		L7NFDEBUG("got sip request\n");
		return 1;
	}

	action got_version
	{
		L7NFDEBUG("got sip version\n");
	}

	action got_sip_response
	{
		L7NFDEBUG("got sip response\n");
		return 1;
	}

	method = ('INVITE'i | 'ACK'i | 'BYE'i | 'CANCEL'i | 'OPTIONS'i | 
			  'REGISTER'i | 'PRACK'i | 'SUBSCRIBE'i | 'NOTIFY'i | 
			  'PUBLISH'i | 'INFO'i | 'REFER'i | 'MESSAGE'i | 'UPDATE'i) %got_method;
	url = ( [^ ]+ ) %got_url;
	sip_version =  'SIP/'i digit {1,2} '.' digit {1,2} %got_version;

	sip_request = ( method . [ \t]+ . url . [ \t]+ . sip_version . '\r'? '\n' ) @got_sip_request;
	sip_response = sip_version . [ \t]+ . digit+ . [^\r\n]* . '\r'? '\n' @got_sip_response;

	sip_filter = sip_request | sip_response;

	main := sip_filter;
}%%

%% write data;

void l7fsm_sip_init(int *state)
{
	int cs = *state;
	%% write init;
	*state = cs;
}

int l7fsm_sip_parse( int *state, const char *data, int len, int isEof )
{
	const char *p = data;
	const char *pe = data + len;

	int cs = *state;
	%% write exec;

	*state = cs;
	if ( cs == l7fsm_sip_error )
		return -1;
	if ( cs >= l7fsm_sip_first_final )
		return 1;
	return 0;
}

