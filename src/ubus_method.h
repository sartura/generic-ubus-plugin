#ifndef _UBUS_METHOD_H_
#define _UBUS_METHOD_H_

#include <libubox/list.h>

// when using name structs starting with 'uom' (ubus object method)

// TODO: change to ubus_method_s
struct ubus_method_s {
	char *name;
	char *message;

	struct list_head list;
};

typedef struct ubus_method_s ubus_method_t;

int ubus_method_create(ubus_method_t **ubus_method, const char *name, const char *message);
int ubus_method_get_name(ubus_method_t *ubus_method, char *name);
int ubus_method_get_message(ubus_method_t *ubus_method, char *message);
void ubus_method_destroy(ubus_method_t **ubus_method);

#endif //_UBUS_METHOD_H_