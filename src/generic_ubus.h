/*
 * @file generic_ubus.h
 * @author Luka Paulic <luka.paulic@sartura.hr>
 *
 * @brief File contains defines and function prototype declarations that
 *        implement the main logic for the generic-ubus plugin.
 *
 * @copyright
 * Copyright (C) 2019 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#ifndef _GENERIC_UBUS_H_
#define _GENERIC_UBUS_H_

/*=========================Includes===========================================*/
#include "context.h"

/*========================Defines=============================================*/
#define YANG_MODEL "terastream-generic-ubus"

#define RPC_UBUS_OBJECT "ubus-object"
#define RPC_UBUS_METHOD "ubus-method"
#define RPC_UBUS_METHOD_MESSAGE "ubus-method-message"
#define RPC_UBUS_INVOCATION "ubus-invocation"
#define RPC_UBUS_INVOCATION_XPATH                                           \
	"/terastream-generic-ubus:ubus-call/ubus-result[ubus-invocation='%s']/" \
	"ubus-invocation"
#define RPC_UBUS_RESPONSE_XPATH                                             \
	"/terastream-generic-ubus:ubus-call/ubus-result[ubus-invocation='%s']/" \
	"ubus-response"
#define RPC_MODULE_PATH_XPATH                  \
	"/terastream-generic-ubus:module-install/" \
	"module-install-result[module-name-full='%s']/module-name-full"
#define RPC_MODULE_RESPONSE_XPATH              \
	"/terastream-generic-ubus:module-install/" \
	"module-install-result[module-name-full='%s']/module-install-status"
#define RPC_FEATURE_INVOCATION_XPATH                       \
	"/terastream-generic-ubus:feature-update/"             \
	"feature-update-result[feature-invocation-full='%s']/" \
	"feature-invocation-full"
#define RPC_FEATURE_RESPONSE_XPATH             \
	"/terastream-generic-ubus:feature-update/" \
	"feature-update-result[feature-invocation-full='%s']/feature-update-status"
#define JSON_EMPTY_OBJECT "{}"

/*=========================Function prototypes================================*/
int generic_ubus_apply_module_changes(context_t *context, const char *module_name, sr_session_ctx_t *session);
int generic_ubus_load_startup_datastore(context_t *context);
void generic_ubus_feature_cb(const char *module_name, const char *feature_name, bool enabled, void *private_ctx);
int generic_ubus_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);
int generic_ubus_ubus_call_rpc_cb(sr_session_ctx_t *session, const char *op_path,
								  const sr_val_t *input, const size_t input_cnt,
								  sr_event_t event, uint32_t request_id,
								  sr_val_t **output, size_t *output_cnt, void *private_data);
int generic_ubus_module_install_rpc_cb(sr_session_ctx_t *session, const char *op_path,
									   const sr_val_t *input, const size_t input_cnt,
									   sr_event_t event, uint32_t request_id,
									   sr_val_t **output, size_t *output_cnt, void *private_data);
void generic_ubus_event_notif_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type,
								 const char *path, const sr_val_t *values, const size_t values_cnt,
								 time_t timestamp, void *private_data);
int generic_ubus_feature_update_rpc_cb(sr_session_ctx_t *session, const char *op_path,
									   const sr_val_t *input, const size_t input_cnt, sr_event_t event,
									   uint32_t request_id, sr_val_t **output, size_t *output_cnt,
									   void *private_data);

#endif //_GENERIC_UBUS_H_
