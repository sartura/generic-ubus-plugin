/*
 * @file generic_ubus.c
 * @author Luka Paulic <luka.paulic@sartura.hr>
 *
 * @brief Implements tha main logic of the generic ubus plugin.
 *        Main functionalities include:
 *          + loading and syncing the startup data store withe the
 *            running data store
 *          + handeling creating, modifying, deleting the ubus object and
 *            ubus method structures according to the configurational data
 *            changes
 *          + retreiving the YANG module state data for a ubus object
 *            that is being monitored
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
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <libyang/tree_data.h>
#include <libyang/tree_schema.h>

#include <srpo_ubus.h>

#include "xpath.h"
#include "common.h"
#include "context.h"
#include "generic_ubus.h"
#include "utils/memory.h"

/*========================Defines=============================================*/
#define YANG_UBUS_OBJECT "ubus-object"
#define YANG_UBUS_METHOD "method"
#define YANG_UBUS_FILTER "ubus-object-filter-file"

/*========================Enumeration=========================================*/
enum generic_ubus_operation_e {
	UBUS_OBJECT_CREATE,
	UBUS_OBJECT_MODIFY,
	UBUS_OBJECT_DELETE,
	UBUS_METHOD_CREATE,
	UBUS_METHOD_MODIFY,
	UBUS_METHOD_DELETE,
	UBUS_FILTER_CREATE,
	UBUS_FILTER_MODIFY,
	UBUS_FILTER_DELETE,
	DO_NOTHING
};

/*===============================Type definition==============================*/
typedef enum generic_ubus_operation_e generic_ubus_operation_t;

/*=========================Function prototypes================================*/
static generic_ubus_operation_t
generic_ubus_get_operation(sr_change_oper_t operation, const struct lyd_node *node);
static int generic_ubus_create_ubus_object(context_t *context, const struct lyd_node *node);
static int generic_ubus_modify_ubus_object(context_t *context, const struct lyd_node *node);
static int generic_ubus_delete_ubus_object(context_t *context, const struct lyd_node *node);
static int generic_ubus_update_filter(context_t *context, const struct lyd_node *node);
static int generic_ubus_create_ubus_method(context_t *context, const struct lyd_node *node);
static int generic_ubus_modify_ubus_method(context_t *context, const struct lyd_node *node);
static int generic_ubus_delete_ubus_method(context_t *context, const struct lyd_node *node);
static int generic_ubus_set_context(context_t *context, const struct lyd_node *node);
static int generic_ubus_operational_cb(sr_session_ctx_t *session, const char *module_name,
									   const char *path, const char *request_xpath,
									   uint32_t request_id, struct lyd_node **parent,
									   void *private_data);
static int generic_ubus_walk_json(json_object *object, struct lys_module *module, struct lyd_node *node);
static void srpo_ubus_get_response_cb(const char *ubus_json, srpo_ubus_result_values_t *values);
/*
static int generic_ubus_set_sysrepo_data(struct lyd_node *root,
                                         sr_val_t **values, size_t *values_cnt);

static int generic_ubus_libyang_to_sysrepo(struct lyd_node_leaf_list *node,
                                           sr_val_t *value);
*/

/*=========================Function definitions===============================*/

/*
 * @brief Loads and sysncs the startup data store with the running data store
 *        if the startup data store is not empty.
 *
 * @param[in] context structure holding the data store context's
 *
 * @return error code.
 */
int generic_ubus_load_startup_datastore(context_t *context)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");

	struct lyd_node *root = NULL;
	struct lyd_node *child = NULL;
	struct lyd_node *next = NULL;
	struct lyd_node *node = NULL;
	char *xpath = "/" YANG_MODEL ":generic-ubus-config//*";

	rc = sr_get_data(context->startup_session, xpath, 0, 0, SR_OPER_DEFAULT, &root);
	if (SR_ERR_NOT_FOUND == rc) {
		INF_MSG("empty startup datastore for context data");
		return SR_ERR_OK;
	} else if (SR_ERR_OK != rc) {
		goto cleanup;
	}

	if (!root)
		goto cleanup;

	LY_TREE_FOR(root->child, child)
	{
		LY_TREE_DFS_BEGIN(child, next, node)
		{
			generic_ubus_set_context(context, node);
			LY_TREE_DFS_END(child, next, node)
		};
	}

cleanup:
	lyd_free(node);
	lyd_free(next);
	lyd_free(child);
	lyd_free(root);

	return rc;
}

/*
 * @brief Syncs the configurational changes in the sysrepo running data store
 *        with the context structure.
 *
 * @param[in] context structure tha holds all necessary plugin data.
 * @param[in] module_name name of the YANG module that has new chagnes.
 * @param[in] session sysrepo session with the module chagnes.
 *
 * @return error code.
 */
int generic_ubus_apply_module_changes(context_t *context, const char *module_name, sr_session_ctx_t *session)
{
	int rc = SR_ERR_OK;
	sr_change_iter_t *it = NULL;
	sr_change_oper_t operation = SR_OP_CREATED;
	const struct lyd_node *node = NULL;
	const char *prev_value = NULL;
	const char *prev_list = NULL;
	bool prev_default = false;

	char xpath[256 + 1] = {0};

	snprintf(xpath, strlen(module_name) + 7, "/%s:*//.", module_name);

	rc = sr_get_changes_iter(session, xpath, &it);
	SR_CHECK_RET(rc, cleanup, "sr_get_change_iter: %s", sr_strerror(rc));

	while (sr_get_change_tree_next(session, it, &operation, &node, &prev_value, &prev_list, &prev_default) == SR_ERR_OK) {
		generic_ubus_operation_t plugin_operation = generic_ubus_get_operation(operation, node);

		switch (plugin_operation) {
			case UBUS_OBJECT_CREATE:
				rc = generic_ubus_create_ubus_object(context, node);
				CHECK_RET_MSG(rc, cleanup, "error while creating ubus_object");
				break;
			case UBUS_OBJECT_MODIFY:
				rc = generic_ubus_modify_ubus_object(context, node);
				CHECK_RET_MSG(rc, cleanup, "error while modifing ubus_object");
				break;
			case UBUS_OBJECT_DELETE:
				rc = generic_ubus_delete_ubus_object(context, node);
				CHECK_RET_MSG(rc, cleanup, "error while deleting ubus_object");
				break;
			case UBUS_METHOD_CREATE:
				rc = generic_ubus_create_ubus_method(context, node);
				CHECK_RET_MSG(rc, cleanup, "error while creating ubus_method");
				break;
			case UBUS_METHOD_MODIFY:
				rc = generic_ubus_modify_ubus_method(context, node);
				CHECK_RET_MSG(rc, cleanup, "error while modifing ubus_method");
				break;
			case UBUS_METHOD_DELETE:
				rc = generic_ubus_delete_ubus_method(context, node);
				CHECK_RET_MSG(rc, cleanup, "error while deleting ubus_method");
				break;
			case UBUS_FILTER_CREATE:
			case UBUS_FILTER_MODIFY:
				rc = generic_ubus_update_filter(context, node);
				CHECK_RET_MSG(rc, cleanup, "error while modifying ubus filter");
				break;
			case UBUS_FILTER_DELETE:
				rc = generic_ubus_update_filter(context, NULL);
				CHECK_RET_MSG(rc, cleanup, "error while deleting ubus filter");
				break;
			default:
				WRN_MSG("operation not supported in plugin");
				break;
		}
	}

cleanup:
	if (it != NULL) {
		sr_free_change_iter(it);
	}

	return rc;
}

/*
 * @brief Determine the generic ubus operation using the sysrepo operation and
 *        new and old values.
 *
 * @param[in] operation sysrepo operation for the current module chagne.
 * @param[in] old_value sysrepo old data store value.
 * @param[in] new_value sysrepo new data store value.
 *
 * @note old_value and new_value can be NULL.
 *
 * @return error code.
 */
static generic_ubus_operation_t
generic_ubus_get_operation(sr_change_oper_t operation, const struct lyd_node *node)
{
	generic_ubus_operation_t plugin_operation = DO_NOTHING;

	int rc = 0;
	char *tail_node = NULL;
	char *node_xpath = lyd_path(node);
	rc = xpath_get_tail_list_node(node_xpath, &tail_node);
	if (rc == SR_ERR_INTERNAL) {
		ERR_MSG("xpath get tail list node error");
		goto cleanup;
	} else if (rc == -2) {
		rc = xpath_get_tail_node(node_xpath, &tail_node);
		if (rc == SR_ERR_INTERNAL) {
			ERR_MSG("xpath get tail list node error");
			goto cleanup;
		}
	}

	if (operation == SR_OP_CREATED) {
		if (node->schema->nodetype == LYS_LIST) {
			if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) {
				plugin_operation = UBUS_OBJECT_CREATE;
			} else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) {
				plugin_operation = UBUS_METHOD_CREATE;
			}
		} else if (node->schema->nodetype == LYS_LEAF) {
			if (strcmp(tail_node, YANG_UBUS_FILTER) == 0) {
				plugin_operation = UBUS_FILTER_CREATE;
			}
		}
	}
	if ((operation == SR_OP_MODIFIED || operation == SR_OP_CREATED)) {
		if (node->schema->nodetype == LYS_LEAF) {
			if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) {
				plugin_operation = UBUS_OBJECT_MODIFY;
			} else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) {
				plugin_operation = UBUS_METHOD_MODIFY;
			} else if (strcmp(tail_node, YANG_UBUS_FILTER) == 0) {
				plugin_operation = UBUS_FILTER_MODIFY;
			}
		}
	}
	if (operation == SR_OP_DELETED) {
		if (node->schema->nodetype == SR_LIST_T || node->schema->nodetype == LYS_LEAF) {
			if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) {
				plugin_operation = UBUS_OBJECT_DELETE;
			} else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) {
				plugin_operation = UBUS_METHOD_DELETE;
			} else if (strcmp(tail_node, YANG_UBUS_FILTER) == 0) {
				plugin_operation = UBUS_FILTER_DELETE;
			}
		}
	}

cleanup:
	FREE_SAFE(tail_node);
	FREE_SAFE(node_xpath);

	return plugin_operation;
}

/*
 * @brief Procedure for creating an ubus_object structure.
 *
 * @param[in] context context for holding the ubus object
 * @param[in] value sysrepo value containing the ubus object information.
 *
 * @return error code.
 */
static int generic_ubus_create_ubus_object(context_t *context, const struct lyd_node *node)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(node, &rc, cleanup, "input argument value is null");

	ubus_object_t *ubus_object = NULL;
	rc = ubus_object_create(&ubus_object);
	CHECK_RET_MSG(rc, cleanup, "allocation ubus_object is null");

	char *key = NULL;
	char *node_xpath = lyd_path(node);
	rc = xpath_get_node_key_value(node_xpath, YANG_UBUS_OBJECT, "name", &key);
	CHECK_RET_MSG(rc, cleanup, "allocation key is null");

	rc = ubus_object_set_name(ubus_object, key);
	CHECK_RET_MSG(rc, cleanup, "set ubus object name error");

	rc = context_add_ubus_object(context, ubus_object);
	CHECK_RET_MSG(rc, cleanup, "add ubus object to list error");

	return rc;

cleanup:
	ubus_object_destroy(&ubus_object);
	FREE_SAFE(node_xpath);
	FREE_SAFE(key);

	return rc;
}

/*
 * @brief Procedure for modifing an ubus_object structure.
 *
 * @param[in] context context for holding the ubus object
 * @param[in] value sysrepo value containing the ubus object information.
 *
 * @note According to the generic ubus YANG module only the yang-module leaf
 *       node can be modifed.
 *
 * @return error code.
 */
static int generic_ubus_modify_ubus_object(context_t *context, const struct lyd_node *node)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(node, &rc, cleanup, "input argument value is null");

	char *node_xpath = lyd_path(node);
	char *key = NULL;
	rc = xpath_get_node_key_value(node_xpath, YANG_UBUS_OBJECT, "name", &key);
	CHECK_RET_MSG(rc, cleanup, "allocation key is null");

	ubus_object_t *ubus_object = NULL;
	rc = context_get_ubus_object(context, &ubus_object, key);
	CHECK_RET_MSG(rc, cleanup, "get ubus object error");

	char *leaf = NULL;
	rc = xpath_get_tail_node(node_xpath, &leaf);
	CHECK_RET_MSG(rc, cleanup, "xpath get tail node");

	if (strcmp("yang-module", leaf) == 0) {
		rc = ubus_object_unsubscribe(context->session, ubus_object);
		CHECK_RET_MSG(rc, cleanup, "unsubscribe error");

		struct lyd_node_leaf_list *node_list = (struct lyd_node_leaf_list *) node;
		rc = ubus_object_set_yang_module(ubus_object, node_list->value_str);
		CHECK_RET_MSG(rc, cleanup, "set ubus object yang module error");

		rc = ubus_object_state_data_subscribe(context->session, (void *) context, ubus_object, generic_ubus_operational_cb);
		CHECK_RET_MSG(rc, cleanup, "module change subscribe error");
		/*
		   rc = ubus_object_init_libyang_data(ubus_object, context->session);
		   CHECK_RET_MSG(rc, cleanup, "init libyang context error");
		   */
	}
	// name attribute is already set when createing ubus object
	// because the name is the key for the ubus object list in YANG module

cleanup:
	FREE_SAFE(node_xpath);
	FREE_SAFE(key);
	FREE_SAFE(leaf);

	return rc;
}

/*
 * @brief Procedure for deleting an ubus_object structure.
 *
 * @param[in] context context for holding the ubus object
 * @param[in] value sysrepo value containing the ubus object information.
 *
 *
 * @return error code.
 */
static int generic_ubus_delete_ubus_object(context_t *context, const struct lyd_node *node)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(node, &rc, cleanup, "input argument value is null");

	char *node_xpath = lyd_path(node);
	char *key = NULL;
	rc = xpath_get_node_key_value(node_xpath, YANG_UBUS_OBJECT, "name", &key);
	CHECK_RET_MSG(rc, cleanup, "allocation key is null");

	if (node->schema->nodetype == LYS_LIST) {
		rc = context_delete_ubus_object(context, key);
		CHECK_RET_MSG(rc, cleanup, "delete ubus object error");
	}
	// name and yang module can't be deleted they are mandatory
	// they can only be modified

cleanup:
	FREE_SAFE(key);
	FREE_SAFE(node_xpath);

	return rc;
}

/*
 * @brief Procedure for creating an ubus_method structure.
 *
 * @param[in] context context for holding the ubus object and ubus method.
 * @param[in] value sysrepo value containing the ubus method information.
 *
 *
 * @return error code.
 */
static int generic_ubus_create_ubus_method(context_t *context, const struct lyd_node *node)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(node, &rc, cleanup, "input argument value is null");

	char *node_xpath = lyd_path(node);
	char *key = NULL;
	rc = xpath_get_node_key_value(node_xpath, YANG_UBUS_OBJECT, "name", &key);
	CHECK_RET_MSG(rc, cleanup, "allocation key is null");

	ubus_object_t *ubus_object = NULL;
	rc = context_get_ubus_object(context, &ubus_object, key);
	CHECK_RET_MSG(rc, cleanup, "get ubus object error");

	FREE_SAFE(key);
	key = NULL;

	rc = xpath_get_node_key_value(node_xpath, YANG_UBUS_METHOD, "name", &key);
	CHECK_RET_MSG(rc, cleanup, "allocation key is null");

	ubus_method_t *ubus_method = NULL;
	rc = ubus_method_create(&ubus_method);
	CHECK_RET_MSG(rc, cleanup, "allocation ubus_method is null");

	rc = ubus_method_set_name(ubus_method, key);
	CHECK_RET_MSG(rc, cleanup, "set ubus method name error");

	rc = ubus_object_add_method(ubus_object, ubus_method);
	CHECK_RET_MSG(rc, cleanup, "add ubus method to list error");

	FREE_SAFE(key);
	FREE_SAFE(node_xpath);
	return rc;

cleanup:
	ubus_method_destroy(&ubus_method);
	FREE_SAFE(key);
	FREE_SAFE(node_xpath);

	return rc;
}

/*
 * @brief Procedure for modifing an ubus_method structure.
 *
 * @param[in] context context for holding the ubus object and ubus method.
 * @param[in] value sysrepo value containing the ubus method information.
 *
 * @note According to the generic ubus YANG module only the message leaf can
 *       be modified.
 *
 * @return error code.
 */
static int generic_ubus_modify_ubus_method(context_t *context, const struct lyd_node *node)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(node, &rc, cleanup, "input argument value is null");

	char *node_xpath = lyd_path(node);
	char *key = NULL;
	rc = xpath_get_node_key_value(node_xpath, YANG_UBUS_OBJECT, "name", &key);
	CHECK_RET_MSG(rc, cleanup, "allocation key is null");

	ubus_object_t *ubus_object = NULL;
	rc = context_get_ubus_object(context, &ubus_object, key);
	CHECK_RET_MSG(rc, cleanup, "get ubus object error");

	FREE_SAFE(key);
	key = NULL;

	rc = xpath_get_node_key_value(node_xpath, YANG_UBUS_METHOD, "name", &key);
	CHECK_RET_MSG(rc, cleanup, "allocation key is null");

	ubus_method_t *ubus_method = NULL;
	rc = ubus_object_get_method(ubus_object, &ubus_method, key);
	CHECK_RET_MSG(rc, cleanup, "get ubus method error");

	char *leaf = NULL;
	rc = xpath_get_tail_node(node_xpath, &leaf);
	CHECK_RET_MSG(rc, cleanup, "xpath get tail node");
	if (strcmp("message", leaf) == 0) {
		struct lyd_node_leaf_list *node_list = (struct lyd_node_leaf_list *) node;
		rc = ubus_method_set_message(ubus_method, node_list->value_str);
		CHECK_RET_MSG(rc, cleanup, "set ubus method message error");
	}

cleanup:
	FREE_SAFE(key);
	FREE_SAFE(leaf);
	FREE_SAFE(node_xpath);

	return rc;
}

/*
 * @brief Procedure for deleting an ubus_method structure.
 *
 * @param[in] context context for holding the ubus object and ubus method.
 * @param[in] value sysrepo value containing the ubus method information.
 *
 *
 * @return error code.
 */
static int generic_ubus_delete_ubus_method(context_t *context, const struct lyd_node *node)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(node, &rc, cleanup, "input argument value is null");

	char *node_xpath = lyd_path(node);
	char *leaf = NULL;
	char *key = NULL;
	rc = xpath_get_node_key_value(node_xpath, YANG_UBUS_OBJECT, "name", &key);
	CHECK_RET_MSG(rc, cleanup, "allocation key is null");

	ubus_object_t *ubus_object = NULL;
	rc = context_get_ubus_object(context, &ubus_object, key);
	CHECK_RET_MSG(rc, cleanup, "get ubus object error");

	FREE_SAFE(key);
	key = NULL;

	rc = xpath_get_node_key_value(node_xpath, YANG_UBUS_METHOD, "name", &key);
	CHECK_RET_MSG(rc, cleanup, "allocation key is null");

	ubus_method_t *ubus_method = NULL;
	rc = ubus_object_get_method(ubus_object, &ubus_method, key);
	CHECK_RET_MSG(rc, cleanup, "get ubus method error");

	if (node->schema->nodetype == LYS_LIST) {
		rc = ubus_object_delete_method(ubus_object, key);
		CHECK_RET_MSG(rc, cleanup, "delete ubus method error");
	} else if (node->schema->nodetype == LYS_LEAF) {
		rc = xpath_get_tail_node(node_xpath, &leaf);
		CHECK_RET_MSG(rc, cleanup, "xpath get tail node");

		if (strcmp("message", leaf) == 0) {
			rc = ubus_method_set_message(ubus_method, NULL);
			CHECK_RET_MSG(rc, cleanup, "set ubus method message error");
		}
	}

cleanup:
	FREE_SAFE(key);
	FREE_SAFE(leaf);
	FREE_SAFE(node_xpath);

	return rc;
}

/*
 * @brief Updating the value of the ubus object filter file name.
 *
 * @param[in] context holding the ubus object and ubus method objects.
 * @param[in] value sysrepo value containing the change.
 *
 * @return error code.
 */
static int generic_ubus_update_filter(context_t *context, const struct lyd_node *node)
{
	int rc = SR_ERR_OK;
	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");

	const char *data = NULL;
	if (node != NULL) {
		struct lyd_node_leaf_list *node_list = (struct lyd_node_leaf_list *) node;
		data = node_list->value_str;
	}

	rc = context_set_ubus_object_filter_file_name(context, data);
	CHECK_RET_MSG(rc, cleanup, "set ubus object filter file name error");

cleanup:
	return rc;
}

/*
 * @brief Main function determineting the generic ubus operation according to
 *        the sysrepo value
 *
 * @param[in] context holding the ubus object and ubus method objects.
 * @param[in] value sysrepo value containing the change.
 *
 * @return error code.
 */
static int generic_ubus_set_context(context_t *context, const struct lyd_node *node)
{
	int rc = SR_ERR_OK;
	struct lyd_node_leaf_list *node_list = NULL;
	const char *node_name = NULL;
	const char *node_value = NULL;

	CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
	CHECK_NULL_MSG(node, &rc, cleanup, "input argument value is null");

	char *node_xpath = lyd_path(node);
	char *tail_node = NULL;
	char *key = NULL;
	rc = xpath_get_tail_node(node_xpath, &tail_node);
	CHECK_RET_MSG(rc, cleanup, "xpath get tail node");

	INF("%s", node_xpath);

	if (strncmp(YANG_UBUS_OBJECT, tail_node, strlen(YANG_UBUS_OBJECT)) == 0 &&
		node->schema->nodetype == LYS_LIST) {
		INF_MSG("create ubus object");
		rc = generic_ubus_create_ubus_object(context, node);
		CHECK_RET_MSG(rc, cleanup, "create ubus object error");

	} else if (strncmp(YANG_UBUS_METHOD, tail_node, strlen(YANG_UBUS_METHOD)) == 0 &&
			   node->schema->nodetype == LYS_LIST) {
		INF_MSG("create ubus method");
		rc = generic_ubus_create_ubus_method(context, node);
		CHECK_RET_MSG(rc, cleanup, "create ubus method error");

	} else if (strncmp(tail_node, "yang-module", strlen(tail_node)) == 0 &&
			   node->schema->nodetype == LYS_LEAF) {
		INF_MSG("modifying ubus object");
		rc = generic_ubus_modify_ubus_object(context, node);
		CHECK_RET_MSG(rc, cleanup, "modify ubus object error");

	} else if (strncmp(tail_node, "message", strlen(tail_node)) == 0 &&
			   node->schema->nodetype == LYS_LEAF) {
		INF_MSG("modify ubus method");
		rc = generic_ubus_modify_ubus_method(context, node);
		CHECK_RET_MSG(rc, cleanup, "modify ubus method error");

	} else if (strncmp(tail_node, YANG_UBUS_FILTER, strlen(tail_node)) == 0 &&
			   node->schema->nodetype == LYS_LEAF) {
		INF_MSG("modify ubus object fitler");
		rc = generic_ubus_update_filter(context, node);
		CHECK_RET_MSG(rc, cleanup, "modify ubus object filter error");

	} else {
		INF_MSG("ignoring the sysrepo value");
	}

cleanup:
	FREE_SAFE(key);
	FREE_SAFE(tail_node);
	FREE_SAFE(node_xpath);

	return rc;
}

/*
 * @brief Callback for gathering ubus state data for a specific ubus YANG module
 *        that is being tracked according to the generic ubus YANG module.
 *
 * @param[in] session sysrepo session for the operational data.
 * @param[in] path xpath for the current element.
 * @param[in/out] parent liyang data node fore returnig the operational data
 * @param[in] request_id request id for a single module.
 * @param[in] requested_xpath original xpath entered by the user.
 * @param[in] private_data context beeing passed to the callback.
 */
static int
generic_ubus_operational_cb(sr_session_ctx_t *session, const char *module_name,
							const char *path, const char *request_xpath,
							uint32_t request_id, struct lyd_node **parent,
							void *private_data)
{

	int rc = SR_ERR_OK;
	char module_whole[256] = {0};
	ubus_object_t *ubus_object_iterator = NULL;
	ubus_method_t *ubus_method_iterator = NULL;
	ubus_object_t *ubus_object = NULL;
	char *ubus_object_name = NULL;
	context_t *context = (context_t *) private_data;
	char *xpath_method_name = NULL;
	char *result_json_data = NULL;
	json_object *parsed_json = NULL;
	struct lyd_node *root = NULL;
	struct lyd_node *root_child = NULL;
	static struct lys_module *libyang_module = NULL;
	sr_conn_ctx_t *connection = NULL;
	const struct ly_ctx *libyang_context = NULL;
	srpo_ubus_result_values_t *values = NULL;
	srpo_ubus_call_data_t ubus_call_data;

	CHECK_NULL_MSG(path, &rc, cleanup, "input argument cb_xpath is null");
	CHECK_NULL_MSG(private_data, &rc, cleanup, "input argument private_ctx is null");

	INF("%s", path);

	context_for_each_ubus_object(context, ubus_object_iterator)
	{
		char *ubus_object_module_name = NULL;
		rc = ubus_object_get_yang_module(ubus_object_iterator, &ubus_object_module_name);
		CHECK_RET_MSG(rc, cleanup, "ubus object get yang module error");
		if (strcmp(ubus_object_module_name, module_name) == 0) {
			ubus_object = ubus_object_iterator;
		}
	}

	if (ubus_object == NULL) {
		goto cleanup;
	}

	INF("%s", request_xpath);

	connection = sr_session_get_connection(session);
	CHECK_NULL_MSG(connection, &rc, cleanup, "sr_session_get_connection error");

	libyang_context = sr_get_context(connection);
	CHECK_NULL_MSG(libyang_context, &rc, cleanup, "sr_get_context error");

	libyang_module = (struct lys_module *) ly_ctx_get_module(libyang_context, module_name, NULL, 1);
	CHECK_NULL_MSG(libyang_module, &rc, cleanup, "ly_ctx_get_module error");

	sprintf(module_whole, "/%s:*", module_name);
	if (strcmp(request_xpath, module_whole) != 0) {
		rc = xpath_get_tail_node(request_xpath, &xpath_method_name);
		CHECK_RET_MSG(rc, cleanup, "xpath get tail node error");
	}

	rc = ubus_object_get_name(ubus_object, &ubus_object_name);
	CHECK_RET_MSG(rc, cleanup, "ubus method get name error");

	root = lyd_new(NULL, libyang_module, module_name);
	CHECK_NULL_MSG(root, &rc, cleanup, "libyang data root node");

	ubus_object_for_each_ubus_method(ubus_object, ubus_method_iterator)
	{
		char *ubus_method_name = NULL;
		rc = ubus_method_get_name(ubus_method_iterator, &ubus_method_name);
		CHECK_RET_MSG(rc, cleanup, "ubus method get name error");

		if ((xpath_method_name && (strcmp(xpath_method_name, ubus_method_name) == 0)) ||
			xpath_method_name == NULL) {
			char *ubus_message = NULL;
			rc = ubus_method_get_message(ubus_method_iterator, &ubus_message);
			CHECK_RET_MSG(rc, cleanup, "ubus method get method message error");

			result_json_data = NULL;
			srpo_ubus_init_result_values(&values);

			ubus_call_data = (srpo_ubus_call_data_t){
				.lookup_path = ubus_object_name, .method = ubus_method_name, .transform_data_cb = srpo_ubus_get_response_cb, .timeout = 0, .json_call_arguments = ubus_message};

			rc = srpo_ubus_call(values, &ubus_call_data);
			CHECK_RET_MSG(rc, cleanup, "ubus call error");

			result_json_data = xstrdup(values->values[0].value);
			srpo_ubus_free_result_values(values);
			values = NULL;

			parsed_json = json_tokener_parse(result_json_data);
			CHECK_NULL_MSG(parsed_json, &rc, cleanup, "tokener parser error");

			root_child = lyd_new(root, libyang_module, ubus_method_name);
			CHECK_NULL_MSG(root_child, &rc, cleanup, "libyang data root is null");

			rc = generic_ubus_walk_json(parsed_json, libyang_module, root_child);
			CHECK_RET_MSG(rc, cleanup, "generic ubus walk json error");

			*parent = root;

			FREE_SAFE(result_json_data);
			result_json_data = NULL;

			if (parsed_json != NULL) {
				json_object_put(parsed_json);
				parsed_json = NULL;
			}

			if (xpath_method_name) {
				break;
			}
		}
	}

	FREE_SAFE(xpath_method_name);

	return rc;

cleanup:
	FREE_SAFE(xpath_method_name);
	FREE_SAFE(result_json_data);

	if (values) {
		srpo_ubus_free_result_values(values);
	}

	if (parsed_json != NULL) {
		json_object_put(parsed_json);
	}

	if (root != NULL) {
		lyd_free_withsiblings(root);
	}

	return rc;
}

/*
 * @brief Walks thorugh the ubus call response JSON data tree and
 *        creates equivelent YANG data tree using predefined converting
 *        rules:
 *          JSON                                |           YANG
 *         -------------------------------------------------------
 *          string                              |   leaf
 *          number                              |   leaf
 *          boolean                             |   leaf
 *          array of {string, number, boolean}  |   leaf-list
 *          array of {array, object}            |   list
 *          object                              |   container
 *
 * @param[in] object json object hodling the data.
 * @param[in] module libyang structure for describing the YANG data model.
 * @param[in] node libyang node that is the root of the tree or subtree.
 *
 * @note Function is recursive.
 *
 * @return error code.
 */
static int generic_ubus_walk_json(json_object *object, struct lys_module *module, struct lyd_node *node)
{
	struct lyd_node *new_node = NULL;
	int rc = SR_ERR_OK;

	json_object_object_foreach(object, key, value)
	{
		json_type type = json_object_get_type(value);
		if (type == json_type_object) {
			new_node = lyd_new(node, module, key);
			CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new node error");
			rc = generic_ubus_walk_json(value, module, new_node);
			CHECK_RET_MSG(rc, cleanup, "error while waking tree");
		} else if (type == json_type_array) {
			size_t json_array_length = json_object_array_length(value);
			for (size_t i = 0; i < json_array_length; i++) {
				json_object *entry = json_object_array_get_idx(value, i);
				json_type type = json_object_get_type(entry);
				if (type == json_type_array || type == json_type_object) {
					new_node = lyd_new(node, module, key);
					CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new node error");
					rc = generic_ubus_walk_json(entry, module, new_node);
					CHECK_RET_MSG(rc, cleanup, "error while waking tree");
				} else {
					new_node = lyd_new_leaf(node, module, key, json_object_get_string(entry));
					CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new leaf error");
				}
			}
		} else {
			new_node = lyd_new_leaf(node, module, key, json_object_get_string(value));
			CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new leaf error");
		}
	}

	return rc;

cleanup:
	if (new_node != NULL) {
		lyd_free_withsiblings(new_node);
	}
	return rc;
}

/*
 * @brief Callback function for handeling configuration data changes for the
 *        generic ubus YANG module.
 *
 * @param[in] session automatically created session used for getting module
 *                    changes. This session must not be stopped.
 * @param[in] module_name module that has changed.
 * @param[in] event sysrepo notification event
 * @param[in] private_ctx context that is being passed to the callback
 *
 * @return error code.
 */
int generic_ubus_change_cb(sr_session_ctx_t *session, const char *module_name,
						   const char *xpath, sr_event_t event, uint32_t request_id,
						   void *private_data)
{
	int rc = SR_ERR_OK;
	context_t *context = (context_t *) private_data;

	INF("%d", event);

	if (SR_EV_DONE == event) {
		/* copy running datastore to startup */
		rc = sr_copy_config(context->startup_session, YANG_MODEL, SR_DS_RUNNING, 0, 0);
		if (SR_ERR_OK != rc) {
			WRN_MSG("Failed to copy running datastore to startup");
			return rc;
		}
		return SR_ERR_OK;
	}

	rc = generic_ubus_apply_module_changes(context, module_name, session);
	return rc;
}

/*
 * @brief Callback for ubus call RPC method. Used to invoke an ubus call and
 *        retreive ubus call result data.
 *
 * @param[in] xpath xpath to the module RPC.
 * @param[in] input sysrepo RPC input data.
 * @param[in] input_cnt number of input data.
 * @param[out] output sysrepo RPC output data to be set.
 * @param[out] output_cnt number of output data.
 * @param[in] private_ctx context being passed to the callback function.
 *
 * @return error code.
 */
int generic_ubus_ubus_call_rpc_cb(sr_session_ctx_t *session, const char *op_path,
								  const sr_val_t *input, const size_t input_cnt,
								  sr_event_t event, uint32_t request_id,
								  sr_val_t **output, size_t *output_cnt, void *private_data)
{
	int rc = SR_ERR_OK;
	char *tail_node = NULL;
	char *ubus_object_name = NULL;
	char *ubus_method_name = NULL;
	char *ubus_message = NULL;
	sr_val_t *result = NULL;
	size_t count = 0;
	char ubus_invoke_string[256 + 1] = {0};
	char *result_json_data = NULL;
	context_t *context = (context_t *) private_data;
	const char *ubus_object_filtered_out_message = "Ubus object is filtered out";
	srpo_ubus_result_values_t *values = NULL;
	srpo_ubus_call_data_t ubus_call_data;

	*output_cnt = 0;

	INF("%d", input_cnt);

	for (int i = 0; i < input_cnt; i++) {
		rc = xpath_get_tail_node(input[i].xpath, &tail_node);
		CHECK_RET_MSG(rc, cleanup, "get tail node error");

		if (strcmp(RPC_UBUS_OBJECT, tail_node) == 0) {
			ubus_object_name = input[i].data.string_val;
		} else if (strcmp(RPC_UBUS_METHOD, tail_node) == 0) {
			ubus_method_name = input[i].data.string_val;
		} else if (strcmp(RPC_UBUS_METHOD_MESSAGE, tail_node) == 0) {
			ubus_message = input[i].data.string_val;
		}

		uint8_t last = (i + 1) >= input_cnt;

		if ((strstr(tail_node, RPC_UBUS_INVOCATION) != NULL &&
			 ubus_method_name != NULL && ubus_object_name != NULL) ||
			last == 1) {
			bool skip_ubus_object = false;
			rc = context_filter_ubus_object(context, ubus_object_name, &skip_ubus_object);
			CHECK_RET_MSG(rc, cleanup, "filter ubus object error");

			INF("%d", skip_ubus_object);
			if (skip_ubus_object == false) {
				srpo_ubus_init_result_values(&values);

				ubus_call_data = (srpo_ubus_call_data_t){
					.lookup_path = ubus_object_name, .method = ubus_method_name, .transform_data_cb = srpo_ubus_get_response_cb, .timeout = 0, .json_call_arguments = ubus_message};

				rc = srpo_ubus_call(values, &ubus_call_data);
				CHECK_RET_MSG(rc, cleanup, "ubus call error");

				result_json_data = xstrdup(values->values[0].value);
				srpo_ubus_free_result_values(values);
				values = NULL;
			} else {
				result_json_data = calloc(1, strlen(ubus_object_filtered_out_message) + 1);
				CHECK_NULL_MSG(result_json_data, &rc, cleanup, "result json data alloc error");
				strcpy(result_json_data, ubus_object_filtered_out_message);
			}

			rc = sr_realloc_values(count, count + 2, &result);
			SR_CHECK_RET(rc, cleanup, "sr realloc values error: %s", sr_strerror(rc));

			memset(ubus_invoke_string, 0, 256 + 1);
			if (ubus_message != NULL) {
				snprintf(ubus_invoke_string, 256 + 1, "%s %s %s", ubus_object_name, ubus_method_name, ubus_message);
			} else {
				snprintf(ubus_invoke_string, 256 + 1, "%s %s %s", ubus_object_name, ubus_method_name, JSON_EMPTY_OBJECT);
			}

			rc = sr_val_build_xpath(&result[count], RPC_UBUS_INVOCATION_XPATH, ubus_invoke_string);
			SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

			rc = sr_val_set_str_data(&result[count], SR_STRING_T, ubus_invoke_string);
			SR_CHECK_RET(rc, cleanup, "sr value set str data: %s", sr_strerror(rc));

			count++;

			rc = sr_val_build_xpath(&result[count], RPC_UBUS_RESPONSE_XPATH, ubus_invoke_string);
			SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

			rc = sr_val_set_str_data(&result[count], SR_STRING_T, result_json_data);
			SR_CHECK_RET(rc, cleanup, "sr value set str data: %s", sr_strerror(rc));

			FREE_SAFE(result_json_data);
			result_json_data = NULL;

			count++;
		}

		FREE_SAFE(tail_node);
		tail_node = NULL;
	}

	*output_cnt = count;
	*output = result;

	return rc;

cleanup:
	FREE_SAFE(tail_node);
	FREE_SAFE(result_json_data);

	if (values) {
		srpo_ubus_free_result_values(values);
	}

	if (result != NULL) {
		sr_free_values(result, count);
	}

	return rc;
}

/*
 * @brief Callback for module install RPC. Used to install modules in sysrepo.
 *
 * @param[in] xpath xpath to the module RPC.
 * @param[in] input sysrepo RPC input data.
 * @param[in] input_cnt number of input data.
 * @param[out] output sysrepo RPC output data to be set.
 * @param[out] output_cnt number of output data.
 * @param[in] private_ctx context being passed to the callback function.
 *
 * @note 'system' call is being used to invoke sysrepoctl command
 *
 * @return error code.
 */
int generic_ubus_module_install_rpc_cb(sr_session_ctx_t *session, const char *op_path,
									   const sr_val_t *input, const size_t input_cnt,
									   sr_event_t event, uint32_t request_id,
									   sr_val_t **output, size_t *output_cnt, void *private_data)
{
	int rc = SR_ERR_OK;
	int src = 0;
	char *path_to_module = NULL;
	char command[256 + 1] = {0};
	char return_message[256 + 1] = {0};
	sr_val_t *return_values = NULL;
	size_t count = 0;
	sr_conn_ctx_t *connection = NULL;

	*output_cnt = 0;

	connection = sr_session_get_connection(session);
	CHECK_NULL_MSG(connection, &rc, cleanup, "session get connection error");

	for (size_t i = 0; i < input_cnt; i++) {
		memset(return_message, 0, 256 + 1);
		memset(command, 0, 256 + 1);

		path_to_module = input[i].data.string_val;
		INF("%s", path_to_module);

		rc = sr_install_module(connection, path_to_module, NULL, NULL, 0);

		if (rc == 0) {
			snprintf(return_message, 256 + 1, "Installation of module %s succeeded", path_to_module);
		} else {
			snprintf(return_message, 256 + 1, "Installation of module %s failed, error: %d", path_to_module, src);
		}
		rc = sr_realloc_values(count, count + 2, &return_values);
		SR_CHECK_RET(rc, cleanup, "sr new values error: %s", sr_strerror(rc));

		rc = sr_val_build_xpath(&return_values[count], RPC_MODULE_PATH_XPATH, path_to_module);
		SR_CHECK_RET(rc, cleanup, "sr set xpath for value error: %s", sr_strerror(rc));

		rc = sr_val_set_str_data(&return_values[count], SR_STRING_T, path_to_module);
		SR_CHECK_RET(rc, cleanup, "sr set string value error: %s", sr_strerror(rc));

		count++;

		rc = sr_val_build_xpath(&return_values[count], RPC_MODULE_RESPONSE_XPATH, path_to_module);
		SR_CHECK_RET(rc, cleanup, "sr set xpath for value error: %s", sr_strerror(rc));

		rc = sr_val_set_str_data(&return_values[count], SR_STRING_T, return_message);
		SR_CHECK_RET(rc, cleanup, "sr set string value error: %s", sr_strerror(rc));

		count++;
	}
	*output_cnt = count;
	*output = return_values;

cleanup:
	return rc;
}

void generic_ubus_event_notif_cb(sr_session_ctx_t *session,
								 const sr_ev_notif_type_t notif_type,
								 const char *path, const sr_val_t *values,
								 const size_t values_cnt, time_t timestamp, void *private_data)
{
	return;
}

/*
 * @brief Callback for feature enable/disable RPC.
 *
 * @param[in] xpath xpath to the module RPC.
 * @param[in] input sysrepo RPC input data.
 * @param[in] input_cnt number of input data.
 * @param[out] output sysrepo RPC output data to be set.
 * @param[out] output_cnt number of output data.
 * @param[in] private_ctx context being passed to the callback function.
 *
 * @note 'system' call is being used to invoke sysrepoctl command
 *
 * @return error code.
 */
int generic_ubus_feature_update_rpc_cb(sr_session_ctx_t *session, const char *op_path,
									   const sr_val_t *input, const size_t input_cnt,
									   sr_event_t event, uint32_t request_id,
									   sr_val_t **output, size_t *output_cnt, void *private_data)
{
	int rc = SR_ERR_OK;
	int src = 0;
	char *tail_node = NULL;
	uint8_t enable_feature = 0;
	char *yang_module_name = NULL;
	char *feature_name = NULL;
	sr_val_t *return_values = NULL;
	size_t count = 0;
	sr_conn_ctx_t *connection = NULL;

	char return_message[256 + 1] = {0};
	char feature_invoke[256 + 1] = {0};

	uint8_t make_sysrepoctl_call = 0;
	*output_cnt = 0;

	connection = sr_session_get_connection(session);
	CHECK_NULL_MSG(connection, &rc, cleanup, "session get connection error");

	for (size_t i = 0; i < input_cnt; i++) {
		rc = xpath_get_tail_node(input[i].xpath, &tail_node);
		CHECK_RET_MSG(rc, cleanup, "get tail node error");

		if (strcmp("module-name", tail_node) == 0) {
			yang_module_name = input[i].data.string_val;
		} else if (strcmp("feature-name", tail_node) == 0) {
			feature_name = input[i].data.string_val;
		} else if (strcmp("enable", tail_node) == 0) {
			enable_feature = 1;
			make_sysrepoctl_call = 1;
		} else if (strcmp("disable", tail_node) == 0) {
			enable_feature = 0;
			make_sysrepoctl_call = 1;
		}

		if (make_sysrepoctl_call == 1) {

			if (enable_feature) {
				rc = sr_enable_module_feature(connection, yang_module_name,
											  feature_name);
			} else {
				rc = sr_disable_module_feature(connection, yang_module_name,
											   feature_name);
			}
			if (rc == 0) {
				snprintf(return_message, 256 + 1, "%s feature %s in module %s succeeded.",
						 (enable_feature == 1) ? "Enabeling" : "Disabeling", feature_name, yang_module_name);
			} else {
				snprintf(return_message, 256 + 1, "%s feature %s in module %s failed. Error: %d.",
						 (enable_feature == 1) ? "Enabeling" : "Disabeling", feature_name, yang_module_name, src);
			}

			snprintf(feature_invoke, 256 + 1, "%s %s", yang_module_name, feature_name);

			rc = sr_realloc_values(count, count + 2, &return_values);
			SR_CHECK_RET(rc, cleanup, "sr realloc values error: %s", sr_strerror(rc));

			rc = sr_val_build_xpath(&return_values[count], RPC_FEATURE_INVOCATION_XPATH, feature_invoke);
			SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

			rc = sr_val_set_str_data(&return_values[count], SR_STRING_T, feature_invoke);
			SR_CHECK_RET(rc, cleanup, "sr value set str data: %s", sr_strerror(rc));

			count++;

			rc = sr_val_build_xpath(&return_values[count], RPC_FEATURE_RESPONSE_XPATH, feature_invoke);
			SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

			rc = sr_val_set_str_data(&return_values[count], SR_STRING_T, return_message);
			SR_CHECK_RET(rc, cleanup, "sr value set str data: %s", sr_strerror(rc));

			count++;
			make_sysrepoctl_call = 0;
		}

		FREE_SAFE(tail_node);
		tail_node = NULL;
	}

	*output_cnt = count;
	*output = return_values;

	return rc;

cleanup:
	FREE_SAFE(tail_node);

	if (return_values != NULL) {
		sr_free_values(return_values, count);
	}

	return rc;
}

/*
 * @brief SRPO ubus response callback
 *
 * @param[in] ubus_json
 * @param[out] values
 *
 */
static void srpo_ubus_get_response_cb(const char *ubus_json, srpo_ubus_result_values_t *values)
{
	values->values = xrealloc(values->values, sizeof(srpo_ubus_result_value_t) * (values->num_values + 1));
	values->values[values->num_values].value = xstrndup(ubus_json, strlen(ubus_json) + 1);
	values->num_values++;

	return;
}

/*=========================Function definitions===============================*/

/*
 * @brief Callback for initializing the plugin. Establishes a connection
 *  	  to the startup datastore and syncs with the running data store.
 * 		  Subscribes to generic ubus YANG module chagne, feature enable,
 * 		  ubus call RPC and module install RPC.
 *
 * @param[in] session session context used for subscribiscions.
 * @param[out] private_ctx context to be used in callback.
 *
 * @return error code.
 *
 */
int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
	INF("%s", __func__);

	int rc = SR_ERR_OK;
	context_t *context = NULL;
	rc = context_create(&context);
	SR_CHECK_RET(rc, cleanup, "%s: context_create: %s", __func__, sr_strerror);

	rc = context_set_session(context, session);
	SR_CHECK_RET(rc, cleanup, "%s: context_create: %s", __func__, sr_strerror);

	*private_ctx = context;

	sr_conn_ctx_t *startup_connection = NULL;
	rc = sr_connect(SR_CONN_DEFAULT, &startup_connection);
	CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

	sr_session_ctx_t *startup_session = NULL;
	rc = sr_session_start(startup_connection, SR_DS_STARTUP, &startup_session);
	CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

	rc = context_set_startup_connection(context, startup_connection);
	SR_CHECK_RET(rc, cleanup, "context error: %s", sr_strerror(rc));

	rc = context_set_startup_session(context, startup_session);
	SR_CHECK_RET(rc, cleanup, "context error: %s", sr_strerror(rc));

	// load startup datastore
	rc = generic_ubus_load_startup_datastore(context);
	SR_CHECK_RET(rc, cleanup, "context error: %s", sr_strerror(rc));

	INF_MSG("Subcribing to module change");
	rc = sr_module_change_subscribe(session, YANG_MODEL, NULL, generic_ubus_change_cb, *private_ctx, 0, SR_SUBSCR_DEFAULT, &context->subscription);
	SR_CHECK_RET(rc, cleanup, "initialization error: %s", sr_strerror(rc));

	INF_MSG("Subscribing to ubus call rpc");
	rc = sr_rpc_subscribe(session, "/" YANG_MODEL ":ubus-call", generic_ubus_ubus_call_rpc_cb, *private_ctx, 0, SR_SUBSCR_CTX_REUSE, &context->subscription);
	SR_CHECK_RET(rc, cleanup, "rpc subscription error: %s", sr_strerror(rc));

	INF_MSG("Subscribing to module install rpc");
	rc = sr_rpc_subscribe(session, "/" YANG_MODEL ":module-install", generic_ubus_module_install_rpc_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &context->subscription);
	SR_CHECK_RET(rc, cleanup, "rpc subscription error: %s", sr_strerror(rc));

	INF_MSG("Subscribing to feature update rpc");
	rc = sr_rpc_subscribe(session, "/" YANG_MODEL ":feature-update", generic_ubus_feature_update_rpc_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &context->subscription);
	SR_CHECK_RET(rc, cleanup, "rpc subscription error: %s", sr_strerror(rc));

	/*
	// TODO: register for each new YANG module individually, maybe unecessary
	INF_MSG("Subscribing to event notification");
	rc = sr_event_notif_subscribe(session, NULL, NULL, (time_t){0}, (time_t){0},
	generic_ubus_event_notif_cb, *private_ctx,
	SR_SUBSCR_CTX_REUSE, &context->subscription);
	SR_CHECK_RET(rc, cleanup, "feature subscription error: %s",
	sr_strerror(rc));
	*/
	INF_MSG("Succesfull init");
	return SR_ERR_OK;

cleanup:
	context_destroy(&context);
	return rc;
}

/*
 * @brief Cleans the private context passed to the callbacks and unsubscribes
 * 		  from all subscriptions.
 *
 * @param[in] session session context for unsubscribing.
 * @param[in] private_ctx context to be released fro memory.
 *
 */
void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
	INF("%s", __func__);
	INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");

	if (NULL != private_ctx) {
		context_t *context = private_ctx;
		context_destroy(&context);
	}
	INF_MSG("Plugin cleaned-up successfully");
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum);

/*
 * @brief Initializes the connection to sysrepo and initializes the plugin.
 * 		  When the program is interupted the cleanup code is called.
 *
 * @return error code.
 *
 */
int main()
{
	int rc = SR_ERR_OK;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_ctx = NULL;

	/* connect to sysrepo */
	INF_MSG("Connecting to sysrepo ...");
	rc = sr_connect(SR_CONN_DEFAULT, &connection);
	SR_CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

	ENABLE_LOGGING(SR_LL_DBG);

	/* start session */
	INF_MSG("Starting session ...");
	rc = sr_session_start(connection, SR_DS_RUNNING, &session);
	SR_CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

	INF_MSG("Initializing plugin ...");
	rc = sr_plugin_init_cb(session, &private_ctx);
	SR_CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1); /* or do some more useful work... */
	}

	sr_plugin_cleanup_cb(session, private_ctx);

cleanup:
	if (NULL != session) {
		rc = sr_session_stop(session);
		if (rc != SR_ERR_OK)
			INF("cleanup: %s", sr_strerror(rc));
	}
	if (NULL != connection) {
		sr_disconnect(connection);
	}
	return rc;
}

/*
 * @brief Termination signal handeling
 *
 * @param[in] signum signal identifier.
 *
 * @note signum is not used.
 */
static void sigint_handler(__attribute__((unused)) int signum)
{
	INF_MSG("Sigint called, exiting...");
	exit_application = 1;
}

#endif
