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

#endif //_UBUS_METHOD_H_