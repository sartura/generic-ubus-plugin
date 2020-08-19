/*
 * @file context.h
 * @author Luka Paulic <luka.paulic@sartura.hr>
 *
 * @brief File contains the definition of context_t structure that is used in
 *        the sysrepo callbacks. Additionally function prototypes that alter
 *        or get the date of the context_t structure are declared here.
 *
 * @copyright
 * Copyright (C) 2019 Deutsche Telekom AG.
 *
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
#ifndef _CONTEXT_H_
#define _CONTEXT_H_

/*================Includes====================================================*/
#include <libubox/list.h>

#include "sysrepo.h"

#include "ubus_object.h"

/*================Structure definition========================================*/
struct context_s {
	sr_session_ctx_t *session;			 // holds the sysrepo session
	sr_subscription_ctx_t *subscription; // structure for sysrepo subscriptions
	sr_session_ctx_t *startup_session;	 // session structure for startup DS
	sr_conn_ctx_t *startup_connection;	 // connection structure for startup DS

	char *ubus_object_filter_file_name;

	struct list_head ubus_object_list; // list of all registered ubus_objects
};

/*===============================Type definition==============================*/
typedef struct context_s context_t;

/*========================Defines=============================================*/
#define context_for_each_ubus_object(__ctx, __uo) \
	list_for_each_entry(__uo, &__ctx->ubus_object_list, list)

/*=========================Function prototypes================================*/
int context_create(context_t **context);
int context_set_session(context_t *context, sr_session_ctx_t *session);
int context_set_subscription(context_t *context, sr_subscription_ctx_t *subscription);
int context_set_startup_session(context_t *context, sr_session_ctx_t *session);
int context_set_startup_connection(context_t *context, sr_conn_ctx_t *connection);
int context_set_ubus_object_filter_file_name(context_t *context, const char *file_name);
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

#endif /* _CONTEXT_UBUS_H_ */
