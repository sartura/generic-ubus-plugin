#ifndef _GENERIC_UBUS_H_
#define _GENERIC_UBUS_H_

#include "context.h"
// used for holding logic data and mapping between sysrepo and plugin

#define YANG_MODEL "terastream-generic-ubus"

#define RPC_UBUS_OBJECT "ubus-object"
#define RPC_UBUS_METHOD "ubus-method"
#define RPC_UBUS_METHOD_MESSAGE "ubus-method-message"
#define RPC_UBUS_INVOCATION "ubus-invocation"
#define RPC_UBUS_INVOCATION_XPATH "/terastream-generic-ubus:ubus-call/ubus-result[ubus-invocation='%s']/ubus-invocation"
#define RPC_UBUS_RESPONSE_XPATH "/terastream-generic-ubus:ubus-call/ubus-result[ubus-invocation='%s']/ubus-response"
#define RPC_MODULE_PATH_XPATH "/terastream-generic-ubus:module-install/module-install-result[module-name-full='%s']/module-name-full"
#define RPC_MODULE_RESPONSE_XPATH "/terastream-generic-ubus:module-install/module-install-result[module-name-full='%s']/module-install-status"
#define RPC_FEATURE_INVOCATION_XPATH "/terastream-generic-ubus:feature-update/feature-update-result[feature-invocation-full='%s']/feature-invocation-full"
#define RPC_FEATURE_RESPONSE_XPATH  "/terastream-generic-ubus:feature-update/feature-update-result[feature-invocation-full='%s']/feature-update-status"
#define JSON_EMPTY_OBJECT "{}"

int generic_ubus_apply_module_changes(context_t *context, const char *module_name, sr_session_ctx_t *session);
int generic_ubus_load_startup_datastore(context_t *context);
void generic_ubus_feature_cb(const char *module_name, const char *feature_name, bool enabled, void *private_ctx);
int generic_ubus_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx);
int generic_ubus_ubus_call_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx);
int generic_ubus_module_install_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx);
int generic_ubus_feature_update_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx);

#endif //_GENERIC_UBUS_H_