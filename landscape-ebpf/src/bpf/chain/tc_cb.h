#ifndef __LD_TC_CB_H_
#define __LD_TC_CB_H_

// Family-indexed chain slots (see chain/tc_stage.h).  Defined here because
// the chain roots do not include tc_stage.h.
#define TC_SLOT_V4 0
#define TC_SLOT_V6 1

// set by pick_wan; read by tc_wan_egress_route to enter chain
#define TC_CHAIN_CB_FORWARDED_OFFSET 0
// set by tc_wan_ingress_root; read by WAN ingress exit
#define TC_CHAIN_CB_L3_OFFSET 1
// set by pick_wan alongside FORWARDED; carries the target WAN link's
// link_chain_id (0 = none) so the egress entry can enter the target
// link's chain without re-resolving the routing decision
#define TC_CHAIN_CB_CHAIN_ID_OFFSET 2

#endif /* __LD_TC_CB_H_ */
