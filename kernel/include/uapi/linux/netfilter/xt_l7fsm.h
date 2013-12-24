#ifndef _XT_L7FSM_H
#define _XT_L7FSM_H

#ifndef __KERNEL__
#include <inttypes.h>
#endif

#define XT_L7FSM_MAX_INFO_SIZE 1024

enum {L7FSM_FILTER_HTTP=0, L7FSM_FILTER_FTP, L7FSM_FILTER_SIP, L7FSM_FILTER_SMTP, L7FSM_FILTER_LAST} l7fsm_filters;
struct xt_l7fsm_info {
	char info[XT_L7FSM_MAX_INFO_SIZE]; 
	uint64_t filters; /* filters mask */
};

#endif /*_XT_L7FSM_H */
