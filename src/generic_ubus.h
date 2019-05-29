#ifndef _GENERIC_UBUS_H_
#define _GENERIC_UBUS_H_

#include "context.h"
// used for holding logic data and mapping between sysrepo and plugin

#define YANG_MODEL "terastream-generic-ubus"

int generic_ubus_apply_module_changes(context_t *context, const char *module_name);
int generic_ubus_load_startup_datastore();

#endif //_GENERIC_UBUS_H_