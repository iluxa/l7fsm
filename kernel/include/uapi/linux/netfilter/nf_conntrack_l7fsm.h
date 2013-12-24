#ifndef _UAPI_NF_CONNTRACK_L7FSM_H
#define _UAPI_NF_CONNTRACK_L7FSM_H

enum l7fsm_matches {L7FSM_MATCH_http, L7FSM_MATCH_ftp, L7FSM_MATCH_smtp, L7FSM_MATCH_sip};

struct l7fsm_state_t {
	int http_state[2];
	int ftp_state[2];
	int smtp_state[2];
	int sip_state[2];

	int match[2]; /* match by side */
	int notmatch;
};

#endif /*_UAPI_NF_CONNTRACK_L7FSM_H */
