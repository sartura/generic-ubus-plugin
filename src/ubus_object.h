#ifndef _UBUS_OBJECT_H_
#define _UBUS_OBJECT_H_

#include <libubox/list.h>

#include "sysrepo.h"

#include "common.h"
#include "ubus_method.h"
#include "context.h"

// when using name structs starting with 'uo' (ubus object)

// yang module config data
struct ubus_object_s {
	char *name;
	char *yang_module;

	sr_subscription_ctx_t *sd_subscription; // ubus module stade data supscription

	//list structure
	struct list_head uom_list;
	struct list_head list;
};

typedef struct ubus_object_s ubus_object_t;

ubus_object_t *uo_create(const char *name, const char *yang_module);
int uo_subscribe(struct global_ctx_s *ctx, ubus_object_t *uo);
int uo_add_method(struct list_head *head, ubus_method_t *method);
int uo_get_name();
int uo_get_yang_module();
ubus_method_t *uo_get_method(const char *method_name);
void uo_destroy(struct global_ctx_s *ctx, ubus_object_t *uo);

#endif // _UBUS_OBJECT_H_