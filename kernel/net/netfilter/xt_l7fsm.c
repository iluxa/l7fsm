/* Xtables module to match packets by level 7 proto using finite state machine
 * Copyright (c) 2013 by Ilya Gavrilov <gilyav@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/filter.h>
#include <net/ip.h>

#include <linux/netfilter.h>
#include <linux/netfilter/xt_l7fsm.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/nf_conntrack_l7fsm.h>

MODULE_AUTHOR("Ilya Gavrilov <gilyav@gmail.com>");
MODULE_DESCRIPTION("Xtables: L7FSM filter match");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_l7fsm");
MODULE_ALIAS("ip6t_l7fsm");

static bool l7fsm_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_l7fsm_info *info = par->matchinfo;
	enum ip_conntrack_info ctinfo;
	bool res = false;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

	if(ct && ct->l7fsm_state) {
		if(info->filters & 1<<L7FSM_FILTER_HTTP) {
			if( (ct->l7fsm_state->match[0] & 1<<L7FSM_MATCH_http) && (ct->l7fsm_state->match[1] & 1<<L7FSM_MATCH_http) )
				res = true;
		}

		if(info->filters & 1<<L7FSM_FILTER_FTP) {
	   		if( (ct->l7fsm_state->match[0] & 1<<L7FSM_MATCH_ftp) && (ct->l7fsm_state->match[1] & 1<<L7FSM_MATCH_ftp) )
	  			res = true;
	 	}

		if(info->filters & 1<<L7FSM_FILTER_SMTP) {
	   		if( (ct->l7fsm_state->match[0] & 1<<L7FSM_MATCH_smtp) && (ct->l7fsm_state->match[1] & 1<<L7FSM_MATCH_smtp) )
	  			res = true;
	 	}

		if(info->filters & 1<<L7FSM_FILTER_SIP) {
	   		if( (ct->l7fsm_state->match[0] & 1<<L7FSM_MATCH_sip) && (ct->l7fsm_state->match[1] & 1<<L7FSM_MATCH_sip) )
	  			res = true;
	 	}
	}
	return res;
}

static struct xt_match l7_mt_reg __read_mostly = {
	.name		= "l7fsm",
	.revision	= 0,
	.family		= NFPROTO_UNSPEC,
	.match		= l7fsm_mt,
	.matchsize	= sizeof(struct xt_l7fsm_info),
	.me		    = THIS_MODULE,
};

static int __init l7_mt_init(void)
{
	return xt_register_match(&l7_mt_reg);
}

static void __exit l7_mt_exit(void)
{
	xt_unregister_match(&l7_mt_reg);
}

module_init(l7_mt_init);
module_exit(l7_mt_exit);
