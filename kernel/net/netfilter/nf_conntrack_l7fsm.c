/*
 * level7 finite state machine  netfilter traking helper
 * Copyright (c) 2013 by Ilya Gavrilov <gilyav@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <linux/netfilter/nf_conntrack_l7fsm.h>

MODULE_AUTHOR("Ilya Gavrilov <gilyav@gmail.com>");
MODULE_DESCRIPTION("l7fsm connection tracking helper");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ip_conntrack_l7fsm");
MODULE_ALIAS_NFCT_HELPER("l7fsm");

#if defined(CONFIG_NF_CONNTRACK_L7FSM_DEBUG)
#define L7NFDEBUG(format, args...)  printk(KERN_DEBUG format , ##args)
#else
#define L7NFDEBUG(format,args...)
#endif

/* l7fsm modules */
#include "l7fsm/l7fsm_http.h"
#include "l7fsm/l7fsm_ftp.h"
#include "l7fsm/l7fsm_smtp.h"
#include "l7fsm/l7fsm_sip.h"

#define l7fsm_init_proto(proto, ct) \
{\
	ct->l7fsm_state->proto##_state[0] = 0;\
	l7fsm_##proto##_init(&ct->l7fsm_state->proto##_state[0]);\
	ct->l7fsm_state->proto##_state[1] = 0;\
	l7fsm_##proto##_init(&ct->l7fsm_state->proto##_state[1]);\
}

#define l7fsm_process_proto(proto, data, len, l7state, side) \
{\
	bool ret = false;\
	\
	if(l7state->notmatch & 1<<L7FSM_MATCH_##proto) {\
		ret = false;\
	} else if( (l7state->match[0] & 1<<L7FSM_MATCH_##proto) && (l7state->match[1] & 1<<L7FSM_MATCH_##proto) ) {\
		ret = true;\
	} else {\
		int res = l7fsm_##proto##_parse(&l7state->proto##_state[side], data, len, false);\
		if(res<0)\
		l7state->notmatch |= 1<<L7FSM_MATCH_##proto;\
		else if(res>0)\
		l7state->match[side] |= 1<<L7FSM_MATCH_##proto;\
		ret = res >=0 ;\
	}\
}

static int l7fsm_init_filters(struct nf_conn *ct, int proto)
{
	if(!ct->l7fsm_state) {
		ct->l7fsm_state = kmalloc(sizeof(struct l7fsm_state_t),GFP_ATOMIC);
		L7NFDEBUG("l7fsm_init_filters nf_conn: %p l7fsm_state: %p\n", ct, ct?ct->l7fsm_state:0);
		if(!ct->l7fsm_state)
			return -ENOMEM;

		ct->l7fsm_state->match[0] = 0;
		ct->l7fsm_state->match[1] = 0;
		ct->l7fsm_state->notmatch = 0;

		if (proto == IPPROTO_TCP) {
			l7fsm_init_proto(http,ct);
			l7fsm_init_proto(ftp,ct);
			l7fsm_init_proto(smtp,ct);
			l7fsm_init_proto(sip,ct);
		} else if (proto == IPPROTO_UDP) {
			l7fsm_init_proto(sip,ct);
		}
	}

	return 0;
}

static int l7fsm_process_tcp(const uint8_t* data, unsigned len, struct nf_conn *ct, int is_request)
{
	int ret = 0;
	if( len == 0 )
		return 0;
	ret = l7fsm_init_filters(ct, IPPROTO_TCP);
	if( ret<0 )
		return ret;

	l7fsm_process_proto(http, data, len, ct->l7fsm_state, is_request);
	l7fsm_process_proto(ftp, data, len, ct->l7fsm_state, is_request);
	l7fsm_process_proto(smtp, data, len, ct->l7fsm_state, is_request);
	l7fsm_process_proto(sip, data, len, ct->l7fsm_state, is_request);

	return ret;
}

static int l7fsm_process_udp(const uint8_t* data, unsigned len, struct nf_conn *ct, int is_request)
{
	int ret = 0;
	if( len == 0 )
		return 0;

	ret = l7fsm_init_filters(ct, IPPROTO_UDP);
	if( ret<0 )
		return ret;

	l7fsm_process_proto(sip, data, len, ct->l7fsm_state, is_request);

	return ret;

}

static int l7fsm_help_tcp(struct sk_buff *skb,
		unsigned int protoff,
		struct nf_conn *ct,
		enum ip_conntrack_info ctinfo)
{
	struct tcphdr *hdr = (struct tcphdr *)(skb->data+protoff);

	char *data = skb->data + protoff + hdr->doff*4;
	int len = skb->len - protoff - hdr->doff*4;

	if( l7fsm_process_tcp(data, len, ct, ctinfo != IP_CT_IS_REPLY?0:1 ) < 0)
		pr_err("l7fsm process_tcp error\n");
	return NF_ACCEPT;
}

static int l7fsm_help_udp(struct sk_buff *skb,
		unsigned int protoff,
		struct nf_conn *ct,
		enum ip_conntrack_info ctinfo)
{
	char *data = skb->data + protoff + 8;
	int len = skb->len - protoff - 8;

	if( l7fsm_process_udp(data, len, ct, ctinfo != IP_CT_IS_REPLY?0:1 ) < 0)
		pr_err("l7fsm process_udp error\n");
	return NF_ACCEPT;
}

static struct nf_conntrack_helper l7fsm_helper_tcp __read_mostly;
static struct nf_conntrack_helper l7fsm_helper_udp __read_mostly;

void l7fsm_destroy(struct nf_conn *ct)
{
	L7NFDEBUG("l7fsm_destroy nf_conn: %p l7fsm_state: %p\n", ct, ct?ct->l7fsm_state:0);
	if( ct && ct->l7fsm_state) {
		kfree(ct->l7fsm_state);
		ct->l7fsm_state = 0;
	}
}

static void nf_conntrack_l7fsm_fini(void)
{
	nf_conntrack_helper_unregister(&l7fsm_helper_tcp);
	nf_conntrack_helper_unregister(&l7fsm_helper_udp);
}

static struct nf_conntrack_expect_policy policy;

static int __init nf_conntrack_l7fsm_init(void)
{
	int ret = 0;
	policy.max_expected = 0;
	policy.timeout = 0;

	l7fsm_helper_tcp.tuple.src.l3num = AF_INET;
	l7fsm_helper_tcp.tuple.dst.protonum = IPPROTO_TCP;
	l7fsm_helper_tcp.expect_policy = &policy;
	l7fsm_helper_tcp.me = THIS_MODULE;
	l7fsm_helper_tcp.help = l7fsm_help_tcp;
	l7fsm_helper_tcp.destroy = l7fsm_destroy;
	sprintf(l7fsm_helper_tcp.name, "l7fsm_tcp");

	ret = nf_conntrack_helper_register(&l7fsm_helper_tcp);
	if ( ret != 0 ) {
		pr_err("l7fsm: failed to register tcp helper\n");
		return ret;
	}

	l7fsm_helper_udp.tuple.src.l3num = AF_INET;
	l7fsm_helper_udp.tuple.dst.protonum = IPPROTO_UDP;
	l7fsm_helper_udp.expect_policy = &policy;
	l7fsm_helper_udp.me = THIS_MODULE;
	l7fsm_helper_udp.help = l7fsm_help_udp;
	l7fsm_helper_udp.destroy = l7fsm_destroy;
	sprintf(l7fsm_helper_udp.name, "l7fsm_udp");

	ret = nf_conntrack_helper_register(&l7fsm_helper_udp);
	if ( ret != 0 ) {
		pr_err("l7fsm: failed to register udp helper\n");
		nf_conntrack_helper_unregister(&l7fsm_helper_tcp);
	}
	return ret;
}

module_init(nf_conntrack_l7fsm_init);
module_exit(nf_conntrack_l7fsm_fini);
