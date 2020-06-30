/*
 * @file context.c
 * @author Luka Paulic <luka.paulic@sartura.hr>
 *
 * @brief Implements getters and setters for the data inside the context_t
 *        structure. Provides functions for retrieving and iterating
 *        over ubus objects. Additionally implements a cleanup function for
 *        releasing the context data from memory.
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

/*================Includes====================================================*/
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "context.h"

/*=========================Function definitions===============================*/

/*
 * @brief Function used for allocating the context_t structure.
 *        Sets all pointers to NULL.
 *
 * @param[in/out] context structer pointer that will be allocated in memory.
 *
 * @return error code.
 */
int context_create(context_t **context)
{
	int rc = SR_ERR_OK;
	*context = calloc(1, sizeof(context_t));
	CHECK_NULL_MSG(*context, &rc, cleanup, "input argument context is null");

	(*context)->session = NULL;
	(*context)->startup_connection = NULL;
	(*context)->startup_session = NULL;
	(*context)->subscription = NULL;
	(*context)->ubus_object_filter_file_name = NULL;
	INIT_LIST_HEAD(&(*context)->ubus_object_list);

cleanup:
	return rc;
}

/*
 * @brief Setter method for the running session.
 *
 * @param[in] context context_t structure to be modified.
 * @param[in] session running session context to be set.
 *
 * @return error code.
 *
 */
int context_set_session(context_t *context, sr_session_ctx_t *session)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(session, &rc, cleanup, "input argument session is null");

	context->session = session;

cleanup:
	return rc;
}

/*
 * @brief Setter method for the subscriptions.
 *
 * @param[in] context context_t structure to be modified.
 * @param[in] subscription subscription context to be set.
 *
 * @return error code.
 */
int context_set_subscription(context_t *context, sr_subscription_ctx_t *subscription)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(subscription, &rc, cleanup, "input argument subscription is null");

	context->subscription = subscription;

cleanup:
	return rc;
}

/*
 * @brief Setter method for the startup session.
 *
 * @param[in] context context_t structure to be modified.
 * @param[in] session startup session context to be set.
 *
 * @return error code.
 */
int context_set_startup_session(context_t *context, sr_session_ctx_t *session)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(session, &rc, cleanup, "input argument session is null");

	context->startup_session = session;

cleanup:
	return rc;
}

/*
 * @brief Setter method for the startup connection.
 *
 * @param[in] context context_t structure to be modified.
 * @param[in] connection startup connection context to be set.
 *
 * @return error code.
 */
int context_set_startup_connection(context_t *context, sr_conn_ctx_t *connection)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(connection, &rc, cleanup, "input argument connection is null");

	context->startup_connection = connection;

cleanup:
	return rc;
}

/*
 * @brief Setter method for the ubus object filter out file.
 *
 * @param[in] context context_t structure to be modified.
 * @param[in] file_name name of the ubus object filter out file.
 *
 * @note path is included in hte file_name
 *
 * @return error code.
 */
int context_set_ubus_object_filter_file_name(context_t *context, const char *file_name)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");

	char *ubus_object_filter_file_name = NULL;

	if (file_name != NULL) {
		ubus_object_filter_file_name = calloc(strlen(file_name) + 1, sizeof(char));
		CHECK_NULL_MSG(ubus_object_filter_file_name, &rc, cleanup, "calloc error");

		strncpy(ubus_object_filter_file_name, file_name, strlen(file_name));
	}

	if (context->ubus_object_filter_file_name != NULL) {
		free(context->ubus_object_filter_file_name);
	}
	context->ubus_object_filter_file_name = ubus_object_filter_file_name;

	return rc;

cleanup:
	free(ubus_object_filter_file_name);
	return rc;
}

/*
 * @brief Getter method for the running session.
 *
 * @param[in] context structure that holds the running session context.
 * @param[out] session  current running session.
 *
 * @return error code.
 */
int context_get_session(context_t *context, sr_session_ctx_t **session)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(context->session, &rc, cleanup, "context session is null");

	*session = context->session;

cleanup:
	return rc;
}

/*
 * @brief Getter method for the subscriptions.
 *
 * @param[in] context structure that holds the subscription context.
 * @param[out] subscription  subscription for the current session.
 *
 * @return error code.
 */
int context_get_subscription(context_t *context, sr_subscription_ctx_t **subscription)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(context->subscription, &rc, cleanup, "context subscription is null");

	*subscription = context->subscription;

cleanup:
	return rc;
}

/*
 * @brief Getter method for the startup session.
 *
 * @param[in] context structure that holds the startup session context.
 * @param[out] session  current startup session.
 *
 * @return error code.
 */
int context_get_startup_session(context_t *context, sr_session_ctx_t **session)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(context->startup_session, &rc, cleanup, "context startup_session is null");

	*session = context->startup_session;

cleanup:
	return rc;
}

/*
 * @brief Getter method for the startup connection.
 *
 * @param[in] context structure that holds the startup connection context.
 * @param[out] connection current startup connection.
 *
 * @return error code.
 */
int context_get_startup_connection(context_t *context, sr_conn_ctx_t **connection)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(context->startup_connection, &rc, cleanup, "context connection is null");

	*connection = context->startup_connection;

cleanup:
	return rc;
}

/*
 * @brief Getter method for a ubus object.
 *
 * @param[in] context structure that holds the ubus object list.
 * @param[out] ubus_object ubus object that was requested.
 * @param[in] ubus_object_name name of the ubus_object to retrieve.
 *
 * @return error code.
 */
int context_get_ubus_object(context_t *context, ubus_object_t **ubus_object, const char *ubus_object_name)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(ubus_object_name, &rc, cleanup, "input argument ubus_object_name is null");

	ubus_object_t *ubus_object_local = NULL;
	list_for_each_entry(ubus_object_local, &context->ubus_object_list, list)
	{
		if (strncmp(ubus_object_local->name, ubus_object_name, strlen(ubus_object_local->name)) == 0)
		{
			*ubus_object = ubus_object_local;
			return rc;
		}
	}
	ERR("%s not found", ubus_object_name);
	rc = SR_ERR_INTERNAL;

cleanup:
	return rc;
}

/*
 * @brief Adds an ubus object to the list of ubus objects.
 *
 * @param[in] context structure that holds the ubus object list.
 * @param[in] ubus_object ubus object to be added to the list.
 *
 * @return error code.
 */
int context_add_ubus_object(context_t *context, ubus_object_t *ubus_object)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");

	list_add(&ubus_object->list, &context->ubus_object_list);

cleanup:
	return rc;
}

/*
 * @brief Removes the ubus_object from the list. Unsubscribes to the YANG module
 *        state data callback and releases the memory allocated
 *        ubus_object.
 *
 * @param[in] context structure that holds the ubus object.
 * @param[in] ubus_object ubus object to be deleted.
 *
 * @return error code.
 */
int context_delete_ubus_object(context_t *context, const char *ubus_object_name)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(ubus_object_name, &rc, cleanup, "input argument ubus_object_name is null");

	ubus_object_t *ubus_object = NULL;
	rc = context_get_ubus_object(context, &ubus_object, ubus_object_name);
	CHECK_RET(rc, cleanup, "ubus method %s not found", ubus_object_name);

	list_del(&ubus_object->list);

	rc = ubus_object_unsubscribe(context->session, ubus_object);
	CHECK_RET_MSG(rc, cleanup, "context unsubscribe ubus object error");

	ubus_object_destroy(&ubus_object);

cleanup:
	return rc;
}

/*
 * @brief Removes all ubus_object from the list. Unsubscribes to the YANG module
 *        state data callback and releases the memory allocated
 *        ubus_object.
 *
 * @param[in] context structure that holds the ubus object.
 * @param[in] ubus_object ubus object to be deleted.
 *
 * @return error code.
 */
int context_delete_all_ubus_object(context_t *context)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	ubus_object_t *ubus_object_p = NULL;
	ubus_object_t *ubus_object_n = NULL;
	list_for_each_entry_safe(ubus_object_p, ubus_object_n, &context->ubus_object_list, list)
	{
		list_del(&ubus_object_p->list);

		rc = ubus_object_unsubscribe(context->session, ubus_object_p);
		CHECK_RET_MSG(rc, cleanup, "context unsubscribe ubus object error");

		ubus_object_destroy(&ubus_object_p);
	}

cleanup:
	return rc;
}

/*
 * @brief Deletes the context structure. Releases all the ubus objects from
 *        memory. Closes the startup session and connection
 *
 * @param[in] context structure that holds the ubus object.
 * @param[in] ubus_object ubus object to be deleted.
 *
 * @return error code.
 */
void context_destroy(context_t **context)
{
	if (*context != NULL) {
		free((*context)->ubus_object_filter_file_name);

		int rc = SR_ERR_OK;
		if ((*context)->startup_session != NULL) {
			rc = sr_session_stop((*context)->startup_session);
			SR_CHECK_RET(rc, cleanup, "sr_session_stop: %s", sr_strerror(rc));
		}
		if ((*context)->startup_connection != NULL) {
			sr_disconnect((*context)->startup_connection);
		}

		rc = context_delete_all_ubus_object(*context);
		CHECK_RET_MSG(rc, cleanup, "context_delete_all_ubus_object error");

		if ((*context)->subscription != NULL) {
			rc = sr_unsubscribe((*context)->subscription);
			SR_CHECK_RET(rc, cleanup, "sr_unsubscribe: %s", sr_strerror(rc));
		}
	}

cleanup:
	free(*context);
	*context = NULL;
}

/*
 * @brief Checks if the ubus object is listed in the ignore file. If so the
 *        state data for the ubus object will not be shown.
 *
 * @param[in] context structure that holds the ubus object.
 * @param[in] ubus_object_name name of the ubus object to be checked.
 * @param[out] skip true if the ubus object is listed in the ignore file,
 *             false otherwise.
 *
 * @return error code.
 */
int context_filter_ubus_object(context_t *context, const char *ubus_object_name, bool *skip)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(ubus_object_name, &rc, cleanup, "input argument ubus_object_name is null");
	*skip = false;
	FILE *fd = NULL;

	if (context->ubus_object_filter_file_name != NULL) {
		struct stat st;
		int result = stat(context->ubus_object_filter_file_name, &st);
		if (result != 0) {
			rc = SR_ERR_OK;
			WRN("file %s does not exist, no filtering will be done", context->ubus_object_filter_file_name);
			return rc;
		}

		fd = fopen(context->ubus_object_filter_file_name, "r");
		if (fd == NULL) {
			rc = SR_ERR_INTERNAL;
			ERR("error opening file %s", context->ubus_object_filter_file_name);
			return rc;
		}

		char file_ubus_object_name[256 + 1];
		regex_t regular_expression;
		int regrc = 0;

		while (true) {
			memset(file_ubus_object_name, 0, 256 + 1);
			int scanned_line = fscanf(fd, "%s\n", file_ubus_object_name);
			if (scanned_line == EOF) {
				break;
			}

			INF("%s", file_ubus_object_name);
			INF("%s", ubus_object_name);

			regrc = regcomp(&regular_expression, file_ubus_object_name, 0);
			if (regrc != 0) {
				rc = SR_ERR_INTERNAL;
			}

			regrc = regexec(&regular_expression, ubus_object_name, 0, NULL, 0);
			if (regrc == 0) {
				INF_MSG("regex match");
				*skip = true;
				regfree(&regular_expression);
				break;
			} else if (regrc == REG_NOMATCH) {
				*skip = false;
				INF_MSG("regex no match");
			} else {
				rc = SR_ERR_INTERNAL;
				ERR("regexec error: %d", regrc);
			}
			regfree(&regular_expression);
		}
	} else {
		rc = SR_ERR_OK;
		WRN_MSG("ubus objec filter file is not set");
		return rc;
	}

cleanup:
	if (fd != NULL) {
		fclose(fd);
	}
	return rc;
}
