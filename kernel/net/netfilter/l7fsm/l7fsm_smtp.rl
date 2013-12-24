/* l7fsm smtp parser module
 * Copyright (c) 2013 by Ilya Gavrilov <gilyav@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

%%{
	machine l7fsm_smtp;

	action got_command
	{
		L7NFDEBUG("got smtp command\n");
   	}

  	action got_command_line
   	{
	   	L7NFDEBUG("got smtp command_line\n");
	   	return 1;
   	}

   	action got_response_line
   	{
	   	L7NFDEBUG("got smtp response_line\n");
	   	return 1;
   	}

    command = ('HELO'i | 'EHLO'i | 'MAIL'i | 'FROM'i | 'RCPT'i | 'TO'i | 
			   'TURN'i | 'ATRN'i | 'SIZE'i | 'ETRN'i | 'PIPELINING'i | 
			   'CHUNKING DATA'i | 'DSN'i | 'RSET'i | 'VRFY'i | 'HELP'i | 
			   'QUIT'i | 'ATRN'i | 'AUTH'i | 'CHUNKING'i | 'DSN'i | 
			   'ETRN'i | 'HELP'i | 'PIPELINING'i | 'SIZE'i | 'STARTTLS'i | 
			   'SMTPUTF8'i | 'UTF8SMTP'i) %got_command;
	command_line =  ( command . [^\r\n]* . '\r'? '\n' )  @got_command_line;

	response_line = (digit {3}) . ('-' | [ \t]+ ) . [^\r\n]* '\r'? '\n' @got_response_line;

    smtp_filter = command_line | response_line;

    main := smtp_filter;
}%%

%% write data;

void l7fsm_smtp_init(int *state)
{
	int cs = *state;
	%% write init;
	*state = cs;
}

int l7fsm_smtp_parse( int *state, const char *data, int len, int isEof )
{
	const char *p = data;
	const char *pe = data + len;

	int cs = *state;
	%% write exec;

	*state = cs;
	if ( cs == l7fsm_smtp_error )
		return -1;
	if ( cs >= l7fsm_smtp_first_final )
		return 1;
	return 0;
}

