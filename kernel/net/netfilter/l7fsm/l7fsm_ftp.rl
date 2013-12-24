/* l7fsm ftp parser module
 * Copyright (c) 2013 by Ilya Gavrilov <gilyav@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

%%{
	machine l7fsm_ftp;

   	action got_ftp_command
	{
		L7NFDEBUG("got ftp_command\n");
		return 1;
	}

	action got_ftp_answer
	{
		L7NFDEBUG("got ftp_answer\n");
		return 1;
	}

	command = ('ABOR'i | 'ACCT'i | 'ADAT'i | 'ALLO'i | 'APPE'i | 'AUTH'i | 
			   'CCC'i | 'CDUP'i | 'CONF'i | 'CWD'i | 'DELE'i | 'ENC'i | 
			   'EPRT'i | 'EPSV'i | 'FEAT'i | 'HELP'i | 'LANG'i | 'LIST'i | 
			   'LPRT'i | 'LPSV'i | 'MDTM'i | 'MIC'i | 'MKD'i | 'MLSD'i | 
			   'MLST'i | 'MODE'i | 'NLST'i | 'NOOP'i | 'OPTS'i | 'PASS'i | 
			   'PASV'i | 'PBSZ'i | 'PORT'i | 'PROT'i | 'PWD'i | 'QUIT'i | 
			   'REIN'i | 'REST'i | 'RETR'i | 'RMD'i | 'RNFR'i | 'RNTO'i | 
			   'SITE'i | 'SIZE'i | 'SMNT'i | 'STAT'i | 'STOR'i | 'STOU'i | 
			   'STRU'i | 'SYST'i | 'TYPE'i | 'USER'i | 'XCUP'i | 'XMKD'i | 
			   'XPWD'i | 'XRCP'i | 'XRMD'i | 'XRSQ'i | 'XSEM'i | 'XSEN'i );
	ftp_command = ( command . ( [ \t]+ . [^\r\n]* . '\r'? '\n' | '\r'? '\n') ) @got_ftp_command;

	ftp_answer = (digit {3}) . ('-' | [ \t]+ ) . [^\r\n]* '\r'? '\n' @got_ftp_answer;

	ftp_filter = ftp_command | ftp_answer;

	main := ftp_filter;
}%%

%% write data;

void l7fsm_ftp_init(int *state)
{
	int cs = *state;
	%% write init;
	*state = cs;
}

int l7fsm_ftp_parse( int *state, const char *data, int len, int isEof )
{
	const char *p = data;
	const char *pe = data + len;

	int cs = *state;
	%% write exec;

	*state = cs;
	if ( cs == l7fsm_ftp_error )
		return -1;
	if ( cs >= l7fsm_ftp_first_final )
		return 1;
	return 0;
}

