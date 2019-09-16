/*
 * @file ubus_call.h
 * @author Luka Paulic <luka.paulic@sartura.hr>
 *
 * @brief File contains function prototypes for abstracting the libubus calls.
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
#ifndef _UBUS_CALL_H_
#define _UBUS_CALL_H_

/*=========================Includes===========================================*/
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

/*=========================Function prototypes================================*/
void ubus_get_response_cb(struct ubus_request *req, int type,
                          struct blob_attr *msg);
int ubus_call(const char *ubus_object_name, const char *ubus_method_name,
              const char *ubus_message,
              void (*f)(struct ubus_request *, int, struct blob_attr *),
              char **result);

#endif //__UBUS_CALL_