/*
 * Xtables l7fsm extension
 *
 * Copyright (c) 2013 by Ilya Gavrilov <gilyav@gmail.com>
 * Licensed under the GNU General Public License version 2 (GPLv2)
 */

#include <linux/netfilter/xt_l7fsm.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <xtables.h>

#define BCODE_FILE_MAX_LEN_B	1024

enum {
	O_FILTER = 0,
};

static void l7fsm_help(void)
{
	printf(
"l7fsm match options:\n"
"--filters <filters>	: filter list separated by comma\n"
"possible filters are: http, ftp, smtp, sip");
}

static const struct xt_option_entry l7fsm_opts[] = {
	{.name = "filters", .id = O_FILTER, .type = XTTYPE_STRING},
	XTOPT_TABLEEND,
};

static void l7fsm_parse(struct xt_option_call *cb)
{
	xtables_option_parse(cb);
	struct xt_l7fsm_info *l7fsm_info;
	char *filter_list;
	switch (cb->entry->id) {
		case O_FILTER:
			l7fsm_info = (void *) cb->data;
			l7fsm_info->filters = 0;
			filter_list = strdup(cb->arg);
			if( strlen(filter_list) > XT_L7FSM_MAX_INFO_SIZE )
				xtables_error(PARAMETER_PROBLEM, "l7fsm: filter list is too long\n");

			char *token;
		   	token = strtok(filter_list,",");
		  	while ( token ) {
		 		if(!strcasecmp(token,"http")) {
					l7fsm_info->filters |= 1<<L7FSM_FILTER_HTTP;
				} else if(!strcasecmp(token,"ftp")) {
					l7fsm_info->filters |= 1<<L7FSM_FILTER_FTP;
				} else if(!strcasecmp(token,"smtp")) {
					l7fsm_info->filters |= 1<<L7FSM_FILTER_SMTP;
				} else if(!strcasecmp(token,"sip")) {
					l7fsm_info->filters |= 1<<L7FSM_FILTER_SIP;
				} else {
	 				l7fsm_info->filters = 0;
					xtables_error(PARAMETER_PROBLEM, "l7fsm: no such filter: %s\n",token);
				}
				token = strtok(NULL,",");
			}
			strncpy(l7fsm_info->info, filter_list, XT_L7FSM_MAX_INFO_SIZE);
			free(filter_list);
			break;
		default:
			xtables_error(PARAMETER_PROBLEM, "l7fsm: unknown option");
	}
}

static void l7fsm_print_info(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_l7fsm_info *l7fsm_info = (void *) match->data;
	printf("%s",l7fsm_info->info);
}

static void l7fsm_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_l7fsm_info *l7fsm_info = (void *) match->data;

	printf(" --filters \"%s,", l7fsm_info->info);
	l7fsm_print_info(ip, match);
	printf("\"");
}

static void l7fsm_fcheck(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & (1 << O_FILTER)))
		xtables_error(PARAMETER_PROBLEM,
				"l7fsm: missing --filters parameter");
}

static void l7fsm_print(const void *ip, const struct xt_entry_match *match,
		int numeric)
{
	printf("match l7fsm ");
	return l7fsm_print_info(ip, match);
}

static struct xtables_match l7fsm_match = {
	.family		= NFPROTO_UNSPEC,
	.name		= "l7fsm",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_l7fsm_info)),
	.userspacesize	= XT_ALIGN(offsetof(struct xt_l7fsm_info, info)),
	.help		= l7fsm_help,
	.print		= l7fsm_print,
	.save		= l7fsm_save,
	.x6_parse	= l7fsm_parse,
	.x6_fcheck	= l7fsm_fcheck,
	.x6_options	= l7fsm_opts,
};

void _init(void)
{
	xtables_register_match(&l7fsm_match);
}
