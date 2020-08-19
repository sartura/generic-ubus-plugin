/*
 * @file ubus_object.h
 * @author Luka Paulic <luka.paulic@sartura.hr>
 *
 * @brief File contains ubus_object_t structure function prototypes declarations
 *        for handeling ubus_object_t specific data.
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
#ifndef _UBUS_OBJECT_H_
#define _UBUS_OBJECT_H_

/*=========================Includes===========================================*/
#include <libubox/list.h>
#include <sysrepo.h>

#include "libyang/libyang.h"
#include "libyang/tree_schema.h"

#include "common.h"
#include "ubus_method.h"

/*================Structure definition========================================*/
struct ubus_object_s {
	char *name;		   // ubus object name
	char *yang_module; // YANG module for ubus storing ubus result data

	sr_subscription_ctx_t *state_data_subscription; // ubus YANG module state
	// data subscription
	// structure

	struct list_head ubus_method_list; // list of ubus methods
	struct list_head list;			   // structure for list
									   // functionalities
};

/*===============================Type definition==============================*/
typedef struct ubus_object_s ubus_object_t;

/*========================Defines=============================================*/
#define ubus_object_for_each_ubus_method(__uo, __uom) \
	list_for_each_entry(__uom, &__uo->ubus_method_list, list)

/*=========================Function prototypes================================*/
int ubus_object_create(ubus_object_t **ubus_object);
int ubus_object_state_data_subscribe(sr_session_ctx_t *session, void *private_ctx,
									 ubus_object_t *ubus_object,
									 int (*f)(sr_session_ctx_t *, const char *, const char *, const char *, uint32_t, struct lyd_node **, void *));

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
