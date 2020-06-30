/*
 * @file ubus_method.c
 * @author Luka Paulic <luka.paulic@sartura.hr>
 *
 * @brief Gives support for manipulating ubus method data: name, message and
 *        cleanup function.
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

/*=========================Includes===========================================*/
#include "ubus_method.h"
#include "common.h"

#include <string.h>

#include <sysrepo.h>

/*=========================Function definitions===============================*/

/*
 * @brief Creates the an ubus_method structure and sets all pointers to NULL.
 *
 * @param[in/out] ubus_method structure to be created and initialized.
 *
 * @return error code.
 */
int ubus_method_create(ubus_method_t **ubus_method)
{
	int rc = SR_ERR_OK;

	*ubus_method = calloc(1, sizeof(ubus_method_t));
	CHECK_NULL_MSG(*ubus_method, &rc, cleanup, "return argument ubus_method is null");

	(*ubus_method)->name = NULL;
	(*ubus_method)->message = NULL;

	return rc;

cleanup:
	free(ubus_method);
	return rc;
}

/*
 * @brief Setter for the ubus method name.
 *
 * @param[in] ubus_method structure to modify.
 * @param[in] name ubus method name to be set.
 *
 * @return error code.
 */
int ubus_method_set_name(ubus_method_t *ubus_method, const char *name)
{
	int rc = SR_ERR_OK;
	char *name_local = NULL;
	CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");
	CHECK_NULL_MSG(name, &rc, cleanup, "input argument name is null");

	name_local = calloc(strlen(name) + 1, sizeof(char));
	CHECK_NULL_MSG(name_local, &rc, cleanup, "memory allocation for name failed");

	strncpy(name_local, name, strlen(name));

	if (ubus_method->name != NULL)
		free(ubus_method->name);

	ubus_method->name = name_local;

	return rc;

cleanup:
	free(name_local);
	return rc;
}

/*
 * @brief Setter for the ubus method message.
 *
 * @param[in] ubus_method structure to modify.
 * @param[in] message ubus method message to be set.
 *
 * @return error code.
 */
int ubus_method_set_message(ubus_method_t *ubus_method, const char *message)
{
	int rc = SR_ERR_OK;
	char *message_local = NULL;
	CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");

	if (message != NULL) {
		message_local = calloc(strlen(message) + 1, sizeof(char));
		CHECK_NULL_MSG(message_local, &rc, cleanup, "memory allocation for message failed");

		strncpy(message_local, message, strlen(message));
	}

	if (ubus_method->message != NULL)
		free(ubus_method->message);

	ubus_method->message = message_local;

	return rc;

cleanup:
	free(message_local);
	return rc;
}

/*
 * @brief Getter for the ubus method name.
 *
 * @param[in] ubus_method structure holdint the data.
 * @param[out] name ubus method name to return.
 *
 * @return error code.
 */
int ubus_method_get_name(ubus_method_t *ubus_method, char **name)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");
	CHECK_NULL_MSG(ubus_method->name, &rc, cleanup, "ubus_metehod name is null");

	*name = ubus_method->name;

cleanup:
	return rc;
}

/*
 * @brief Getter for the ubus method message.
 *
 * @param[in] ubus_method structure holdint the data.
 * @param[out] name ubus method message to return.
 *
 * @return error code.
 */
int ubus_method_get_message(ubus_method_t *ubus_method, char **message)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");

	*message = ubus_method->message;

cleanup:
	return rc;
}

/*
 * @brief releases the memory for the ubus_method structure.
 *        Sets the pointer to NULL.
 *
 * @param[in] ubus_method pointer to the ubus_method structure to be freed.
 */
void ubus_method_destroy(ubus_method_t **ubus_method)
{
	if (*ubus_method != NULL) {
		free((*ubus_method)->name);
		free((*ubus_method)->message);
	}

	free(*ubus_method);
	*ubus_method = NULL;
}
