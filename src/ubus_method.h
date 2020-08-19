/*
 * @file ubus_method.h
 * @author Luka Paulic <luka.paulic@sartura.hr>
 *
 * @brief File contains ubus_method_t structure function prototypes declarations
 *        for handeling ubus_method_t specific data.
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
#ifndef _UBUS_METHOD_H_
#define _UBUS_METHOD_H_

/*=========================Includes===========================================*/
#include <libubox/list.h>

/*================Structure definition========================================*/
struct ubus_method_s {
	char *name;	   // ubus method name
	char *message; // ubus method message in JSON format

	struct list_head list; // structure for list functionalities
};

/*===============================Type definition==============================*/
typedef struct ubus_method_s ubus_method_t;

/*=========================Function prototypes================================*/
int ubus_method_create(ubus_method_t **ubus_method);
int ubus_method_set_name(ubus_method_t *ubus_method, const char *name);
int ubus_method_set_message(ubus_method_t *ubus_method, const char *message);
int ubus_method_get_name(ubus_method_t *ubus_method, char **name);
int ubus_method_get_message(ubus_method_t *ubus_method, char **message);
void ubus_method_destroy(ubus_method_t **ubus_method);

#endif //_UBUS_METHOD_H_
