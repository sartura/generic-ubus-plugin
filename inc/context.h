// #includes for below definitions
#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include <libubox/list.h>

#include "sysrepo.h"

#include "ubus_object.h"

struct context_s {
	sr_session_ctx_t *session;			// session for a connection running DS
	sr_subscription_ctx_t *subscription;	// subscription for generic-ubus
	sr_session_ctx_t *startup_session;			// session for a connection running DS
	sr_conn_ctx_t *startup_connection;

	// filtering support
	int inotify_fd;
	int inotify_wd; // 1 file tracking only 2 types of events

	struct list_head ubus_object_list; // list of all registered ubus_objects
};

typedef struct context_s context_t;

#define context_for_each_ubus_object(__ctx, __uo)	\
list_for_each_entry(__uo, &__ctx->ubus_object_list, list)

int context_create(context_t **context);
int context_set_session(context_t *context, sr_session_ctx_t *session);
int context_set_subscription(context_t *context, sr_subscription_ctx_t *subscription);
int context_set_startup_session(context_t *context, sr_session_ctx_t *session);
int context_set_startup_connection(context_t *context, sr_conn_ctx_t *connection);
int context_get_session(context_t *context, sr_session_ctx_t **session);
int context_get_subscription(context_t *context, sr_subscription_ctx_t **subscription);
int context_get_startup_session(context_t *context, sr_session_ctx_t **session);
int context_get_startup_connection(context_t *context, sr_conn_ctx_t **connection);
int context_get_ubus_object(context_t *context, ubus_object_t **ubus_object, const char *ubus_object_name);
int context_add_ubus_object(context_t *context, ubus_object_t *ubus_object);
int context_delete_ubus_object(context_t *context, const char *ubus_object_name);
int context_delete_all_ubus_object(context_t *context);
void context_destroy(context_t **context);

int context_filter_ubus_object(context_t *context, const char *ubus_object_name, bool *skip);

// filter support
/*
int context_init_ubus_object_filter();
int context_destroy_ubus_object_filter();
int context_filter_ubus_object();
*/
#endif /* _CONTEXT_UBUS_H_ */