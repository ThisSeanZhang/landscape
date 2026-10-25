#ifndef __LD_TC_CB_H_
#define __LD_TC_CB_H_

#include <vmlinux.h>

#include "reader/skb_ferry.h"

// Family-indexed chain slots (see chain/tc_stage.h).  Defined here because
// the chain roots do not include tc_stage.h.
#define TC_SLOT_V4 0
#define TC_SLOT_V6 1

#endif /* __LD_TC_CB_H_ */
