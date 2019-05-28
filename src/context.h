// #includes for below definitions
#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include <libubox/list.h>

#include "sysrepo.h"

struct global_ctx_s {
	sr_session_ctx_t *session;			// session for a connection running DS
	sr_subscription_ctx_t *subscription;	// subscription for generic-ubus
	sr_session_ctx_t *session_startup;			// session for a connection running DS
	sr_conn_ctx_t *connection_startup;
	struct list_head uo_list; // list of all registered ubus_objects
};

// TODO: add libyang structures for the state data for each registered ubus object
#endif /* _CONTEXT_UBUS_H_ */