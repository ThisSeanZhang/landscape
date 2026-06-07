#ifndef __LD_TC_CB_H_
#define __LD_TC_CB_H_

// set by pick_wan; read by tc_wan_egress_intro to enter chain
#define TC_CHAIN_CB_FORWARDED_OFFSET 0
// set by tc_wan_chain_ingress_root; read by WAN ingress exit
#define TC_CHAIN_CB_L3_OFFSET 1

#endif /* __LD_TC_CB_H_ */
