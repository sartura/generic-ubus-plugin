#ifndef _UBUS_OBJECT_H_
#define _UBUS_OBJECT_H_

#include <libubox/list.h>

#include "common.h"
#include "ubus_method.h"

// yang module config data
struct ubus_object_s {
	char *name;
	char *yang_module;

	sr_subscription_ctx_t *state_data_subscription;

	//list structure
	struct list_head ubus_method_list;
	struct list_head list;
};

typedef struct ubus_object_s ubus_object_t;

#define ubus_object_for_each_ubus_method(__uo, __uom)	\
list_for_each_entry(__uom, &__uo->ubus_method_list, list)

int ubus_object_create(ubus_object_t **ubus_object);
int ubus_object_subscribe(sr_session_ctx_t *session, void *private_ctx, ubus_object_t *ubus_object, int (*f)(const char *, sr_val_t **, size_t *, uint64_t, const char *, void *));
int ubus_object_set_name(ubus_object_t *ubus_object, const char *name);
int ubus_object_set_yang_module(ubus_object_t *ubus_object, const char *yang_module);
int ubus_object_unsubscribe(sr_session_ctx_t *session, ubus_object_t *ubus_object);
int ubus_object_add_method(ubus_object_t *ubus_object, ubus_method_t *ubus_method);
int ubus_object_delete_method(ubus_object_t *ubus_object, const char *method_name);
int ubus_object_delete_all_methods(ubus_object_t *ubus_object);
int ubus_object_get_name(ubus_object_t *ubus_object, char **name);
int ubus_object_get_yang_module(ubus_object_t *ubus_object, char **yang_module);
int ubus_object_get_method(ubus_object_t *ubus_object, ubus_method_t **ubus_method, const char *method_name);
void ubus_object_destroy(ubus_object_t **ubus_object);


#endif // _UBUS_OBJECT_H_