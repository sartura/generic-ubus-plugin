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
#include "generic_ubus.h"
#include "xpath.h"

#include "sysrepo/values.h"

#include "libyang/tree_data.h"
#include "libyang/tree_schema.h"

#include "ubus_call.h"

/*========================Defines=============================================*/
#define YANG_UBUS_OBJECT "ubus-object"
#define YANG_UBUS_METHOD "method"
#define YANG_UBUS_FILTER "ubus-object-filter-file"

/*========================Enumeration=========================================*/
enum generic_ubus_operation_e { UBUS_OBJECT_CREATE,
                                UBUS_OBJECT_MODIFY,
                                UBUS_OBJECT_DELETE,
                                UBUS_METHOD_CREATE,
                                UBUS_METHOD_MODIFY,
                                UBUS_METHOD_DELETE,
                                UBUS_FILTER_CREATE,
                                UBUS_FILTER_MODIFY,
                                UBUS_FILTER_DELETE,
                                DO_NOTHING };

/*===============================Type definition==============================*/
typedef enum generic_ubus_operation_e generic_ubus_operation_t;

/*=========================Function prototypes================================*/
static generic_ubus_operation_t generic_ubus_get_operation(sr_change_oper_t operation, sr_val_t *old_value, sr_val_t *new_value);
static int generic_ubus_create_ubus_object(context_t *context, sr_val_t *value);
static int generic_ubus_modify_ubus_object(context_t *context, sr_val_t *value);
static int generic_ubus_delete_ubus_object(context_t *context, sr_val_t *value);
static int generic_ubus_update_filter(context_t *context, sr_val_t *value);
static int generic_ubus_create_ubus_method(context_t *context, sr_val_t *value);
static int generic_ubus_modify_ubus_method(context_t *context, sr_val_t *value);
static int generic_ubus_delete_ubus_method(context_t *context, sr_val_t *value);
static int generic_ubus_set_context(context_t *context, sr_val_t *value);
static int generic_ubus_operational_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx);
static int generic_ubus_walk_json(json_object *object, struct lys_module *module, struct lyd_node *node);
static int generic_ubus_set_sysrepo_data(struct lyd_node *root, sr_val_t **values, size_t *values_cnt);
static int generic_ubus_libyang_to_sysrepo(struct lyd_node_leaf_list *node, sr_val_t *value);

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

    sr_val_t *values = NULL;
    size_t count = 0;
    char *xpath = "/"YANG_MODEL":generic-ubus-config//*";

    rc = sr_get_items(context->startup_session, xpath, &values, &count);
    if (SR_ERR_NOT_FOUND == rc) {
        INF_MSG("empty startup datastore for context data");
        return SR_ERR_OK;
    } else if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    INF("setting context data: %d", count);
    for (size_t i = 0; i < count; i++)
    {
        generic_ubus_set_context(context, &(values[i]));
    }

cleanup:
    if (values != NULL && 0 < count) {
        sr_free_values(values, count);
    }
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
    sr_change_oper_t operation;
    sr_change_iter_t *it = NULL;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;

    char xpath[256+1] = {0};

    snprintf(xpath, strlen(module_name) + 4, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, xpath, &it);
    SR_CHECK_RET(rc, cleanup, "sr_get_change_iter: %s", sr_strerror(rc));

    while (1)
    {
        int cont = sr_get_change_next(session, it, &operation, &old_value, &new_value);
        if (cont != SR_ERR_OK) { break; }

        generic_ubus_operation_t plugin_operation = generic_ubus_get_operation(operation, old_value, new_value);

        switch(plugin_operation)
        {
            case UBUS_OBJECT_CREATE:
                rc = generic_ubus_create_ubus_object(context, new_value);
                CHECK_RET_MSG(rc, cleanup, "error while creating ubus_object");
                break;
            case UBUS_OBJECT_MODIFY:
                rc = generic_ubus_modify_ubus_object(context, new_value);
                CHECK_RET_MSG(rc, cleanup, "error while modifing ubus_object");
                break;
            case UBUS_OBJECT_DELETE:
                rc = generic_ubus_delete_ubus_object(context, old_value);
                CHECK_RET_MSG(rc, cleanup, "error while deleting ubus_object");
                break;
            case UBUS_METHOD_CREATE:
                rc = generic_ubus_create_ubus_method(context, new_value);
                CHECK_RET_MSG(rc, cleanup, "error while creating ubus_method");
                break;
            case UBUS_METHOD_MODIFY:
                rc = generic_ubus_modify_ubus_method(context, new_value);
                CHECK_RET_MSG(rc, cleanup, "error while modifing ubus_method");
                break;
            case UBUS_METHOD_DELETE:
                rc = generic_ubus_delete_ubus_method(context, old_value);
                CHECK_RET_MSG(rc, cleanup, "error while deleting ubus_method");
                break;
            case UBUS_FILTER_CREATE:
            case UBUS_FILTER_MODIFY:
                rc = generic_ubus_update_filter(context, new_value);
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

        sr_free_val(old_value);
        sr_free_val(new_value);
    }
    old_value = NULL;
    new_value = NULL;

cleanup:
    if (old_value != NULL) { sr_free_val(old_value); }
    if (new_value != NULL) { sr_free_val(new_value); }
    if (it != NULL) { sr_free_change_iter(it); }
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
static generic_ubus_operation_t generic_ubus_get_operation(sr_change_oper_t operation, sr_val_t *old_value, sr_val_t *new_value)
{
    generic_ubus_operation_t plugin_operation = DO_NOTHING;

    char *tail_node = NULL;
    const char *xpath = (new_value != NULL) ? new_value->xpath : ((old_value != NULL) ? old_value->xpath : NULL);
    int rc = 0;
    INF("%s", xpath);
    rc = xpath_get_tail_list_node(xpath, &tail_node);
    if (rc == SR_ERR_INTERNAL)
    {
        ERR_MSG("xpath get tail list node error");
        goto cleanup;
    }
    else if (rc == -2)
    {
        rc = xpath_get_tail_node(xpath, &tail_node);
        if (rc == SR_ERR_INTERNAL)
        {
            ERR_MSG("xpath get tail list node error");
            goto cleanup;
        }
    }

    if (operation == SR_OP_CREATED && new_value != NULL && old_value == NULL)
    {
        if (new_value->type == SR_LIST_T)
        {
            if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) { plugin_operation = UBUS_OBJECT_CREATE; }
            else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) { plugin_operation = UBUS_METHOD_CREATE;}
        }
        else if (new_value->type == SR_STRING_T)
        {
            if (strcmp(tail_node, YANG_UBUS_FILTER) == 0) { plugin_operation = UBUS_FILTER_CREATE; }
        }
    }
    if ((operation == SR_OP_MODIFIED || operation == SR_OP_CREATED) && new_value != NULL)
    {
        if (new_value->type == SR_STRING_T)
        {
            if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) { plugin_operation = UBUS_OBJECT_MODIFY; }
            else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) { plugin_operation = UBUS_METHOD_MODIFY; }
            else if (strcmp(tail_node, YANG_UBUS_FILTER) == 0) { plugin_operation = UBUS_FILTER_MODIFY; }
        }
    }
    if (operation == SR_OP_DELETED && old_value != NULL && new_value ==  NULL)
    {
        if (old_value->type == SR_LIST_T || old_value->type == SR_STRING_T)
        {
            if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) { plugin_operation = UBUS_OBJECT_DELETE; }
            else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) { plugin_operation = UBUS_METHOD_DELETE; }
            else if (strcmp(tail_node, YANG_UBUS_FILTER) == 0) { plugin_operation = UBUS_FILTER_DELETE; }
        }

    }

cleanup:
    free(tail_node);
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
static int generic_ubus_create_ubus_object(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    ubus_object_t *ubus_object = NULL;
    rc = ubus_object_create(&ubus_object);
    CHECK_RET_MSG(rc, cleanup, "allocation ubus_object is null");

    char *key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_OBJECT, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    rc = ubus_object_set_name(ubus_object, key);
    CHECK_RET_MSG(rc, cleanup, "set ubus object name error");

    rc = context_add_ubus_object(context, ubus_object);
    CHECK_RET_MSG(rc, cleanup, "add ubus object to list error");

    free(key);
    return rc;

cleanup:
    ubus_object_destroy(&ubus_object);
    free(key);
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
static int generic_ubus_modify_ubus_object(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    char *key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_OBJECT, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    ubus_object_t *ubus_object = NULL;
    rc = context_get_ubus_object(context, &ubus_object, key);
    CHECK_RET_MSG(rc, cleanup, "get ubus object error");

    char *leaf = NULL;
    rc = xpath_get_tail_node(value->xpath, &leaf);
    CHECK_RET_MSG(rc, cleanup, "xpath get tail node");

    if (strcmp("yang-module", leaf) == 0)
    {
        rc = ubus_object_unsubscribe(context->session, ubus_object);
        CHECK_RET_MSG(rc, cleanup, "unsubscribe error");

        rc = ubus_object_set_yang_module(ubus_object, value->data.string_val);
        CHECK_RET_MSG(rc, cleanup, "set ubus object yang module error");

        rc = ubus_object_state_data_subscribe(context->session, (void *)context, ubus_object, generic_ubus_operational_cb);
        CHECK_RET_MSG(rc, cleanup, "module change subscribe error");

        rc = ubus_object_init_libyang_data(ubus_object, context->session);
        CHECK_RET_MSG(rc, cleanup, "init libyang context error");
    }
    // name attribute is already set when createing ubus object
    // because the name is the key for the ubus object list in YANG module

cleanup:
    free(key);
    free(leaf);
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
static int generic_ubus_delete_ubus_object(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    char *key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_OBJECT, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    if (value->type == SR_LIST_T)
    {
        rc = context_delete_ubus_object(context, key);
        CHECK_RET_MSG(rc, cleanup, "delete ubus object error");
    }
    // name and yang module can't be deleted they are mandatory
    // they can only be modified

cleanup:
    free(key);
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
static int generic_ubus_create_ubus_method(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    char *key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_OBJECT, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    ubus_object_t *ubus_object = NULL;
    rc = context_get_ubus_object(context, &ubus_object, key);
    CHECK_RET_MSG(rc, cleanup, "get ubus object error");

    free(key);
    key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_METHOD, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    ubus_method_t *ubus_method = NULL;
    rc = ubus_method_create(&ubus_method);
    CHECK_RET_MSG(rc, cleanup, "allocation ubus_method is null");

    rc = ubus_method_set_name(ubus_method, key);
    CHECK_RET_MSG(rc, cleanup, "set ubus method name error");

    rc = ubus_object_add_method(ubus_object, ubus_method);
    CHECK_RET_MSG(rc, cleanup, "add ubus method to list error");

    free(key);
    return rc;

cleanup:
    ubus_method_destroy(&ubus_method);
    free(key);
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
static int generic_ubus_modify_ubus_method(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    char *key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_OBJECT, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    ubus_object_t *ubus_object = NULL;
    rc = context_get_ubus_object(context, &ubus_object, key);
    CHECK_RET_MSG(rc, cleanup, "get ubus object error");

    free(key);
    key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_METHOD, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    ubus_method_t *ubus_method = NULL;
    rc = ubus_object_get_method(ubus_object, &ubus_method, key);
    CHECK_RET_MSG(rc, cleanup, "get ubus method error");

    char *leaf = NULL;
    rc = xpath_get_tail_node(value->xpath, &leaf);
    CHECK_RET_MSG(rc, cleanup, "xpath get tail node");
    if (strcmp("message", leaf) == 0)
    {
        rc = ubus_method_set_message(ubus_method, value->data.string_val);
        CHECK_RET_MSG(rc, cleanup, "set ubus method message error");
    }

cleanup:
    free(key);
    free(leaf);
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
static int generic_ubus_delete_ubus_method(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    char *leaf = NULL;
    char *key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_OBJECT, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    ubus_object_t *ubus_object = NULL;
    rc = context_get_ubus_object(context, &ubus_object, key);
    CHECK_RET_MSG(rc, cleanup, "get ubus object error");

    free(key);
    key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_METHOD, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    ubus_method_t *ubus_method = NULL;
    rc = ubus_object_get_method(ubus_object, &ubus_method, key);
    CHECK_RET_MSG(rc, cleanup, "get ubus method error");

    if (value->type == SR_LIST_T)
    {
        rc = ubus_object_delete_method(ubus_object, key);
        CHECK_RET_MSG(rc, cleanup, "delete ubus method error");
    }
    else if (value->type == SR_STRING_T)
    {
        rc = xpath_get_tail_node(value->xpath, &leaf);
        CHECK_RET_MSG(rc, cleanup, "xpath get tail node");
        if (strcmp("message", leaf) == 0)
        {
            rc = ubus_method_set_message(ubus_method, NULL);
            CHECK_RET_MSG(rc, cleanup, "set ubus method message error");
        }
    }

cleanup:
    free(key);
    free(leaf);
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
static int generic_ubus_update_filter(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");

    char *data = NULL;

    if (value != NULL)
    {
        data = value->data.string_val;
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
static int generic_ubus_set_context(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    char *tail_node = NULL;
    char *key = NULL;
    ubus_object_t *ubus_object = NULL;
    ubus_method_t *ubus_method = NULL;
    rc = xpath_get_tail_node(value->xpath, &tail_node);
    CHECK_RET_MSG(rc, cleanup, "xpath get tail node");

    INF("%s", value->xpath);

    if (strncmp(YANG_UBUS_OBJECT, tail_node, strlen(YANG_UBUS_OBJECT)) == 0 && value->type == SR_LIST_T)
    {
        INF_MSG("create ubus object");
        rc = generic_ubus_create_ubus_object(context, value);
        CHECK_RET_MSG(rc, cleanup, "create ubus object error");
    }
    else if (strncmp(YANG_UBUS_METHOD, tail_node, strlen(YANG_UBUS_METHOD)) == 0 && value->type == SR_LIST_T)
    {
        INF_MSG("create ubus method");
        rc = generic_ubus_create_ubus_method(context, value);
        CHECK_RET_MSG(rc, cleanup, "create ubus method error");
    }
    else if (strncmp(tail_node, "yang-module", strlen(tail_node)) == 0 && value->type == SR_STRING_T)
    {
        INF_MSG("modifying ubus object");
        rc = generic_ubus_modify_ubus_object(context, value);
        CHECK_RET_MSG(rc, cleanup, "modify ubus object error");
    }
    else if (strncmp(tail_node, "message", strlen(tail_node)) == 0 && value->type == SR_STRING_T)
    {
        INF_MSG("modify ubus method");
        rc = generic_ubus_modify_ubus_method(context, value);
        CHECK_RET_MSG(rc, cleanup, "modify ubus method error");
    }
    else if (strncmp(tail_node, YANG_UBUS_FILTER, strlen(tail_node)) == 0 && value->type == SR_STRING_T)
    {
        INF_MSG("modify ubus object fitler");
        rc = generic_ubus_update_filter(context, value);
        CHECK_RET_MSG(rc, cleanup, "modify ubus object filter error");
    }
    else
    {
        INF_MSG("ignoring the sysrepo value");
    }

    free(key);
    free(tail_node);
    return rc;

cleanup:
    free(key);
    free(tail_node);
    ubus_object_destroy(&ubus_object);
    ubus_method_destroy(&ubus_method);
    return rc;
}

/*
 * @brief Callback function for enabeling/disabeling features in YANG modules
 *
 * @param[in] module_name name of the module for which a feature is
 *                        beeing updated.
 * @param[in] feature_name name of the feature that is being updated.
 * @param[in] enabled true if the feature is enabled, false otherwise.
 * @param[in] private_ctx context tha is beeing passed to the callback
 *
 * @note features will be update only for the modules tracked by the generic
 *       ubus plugin.
 *
*/
void generic_ubus_feature_cb(const char *module_name, const char *feature_name, bool enabled, void *private_ctx)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(private_ctx, &rc, cleanup, "input argument private_ctx is null");
    context_t *context = (context_t *)private_ctx;
    ubus_object_t *ubus_object_it = NULL;
    ubus_object_t *ubus_object = NULL;
    context_for_each_ubus_object(context, ubus_object_it)
    {
        char *ubus_object_module_name = NULL;
        rc = ubus_object_get_yang_module(ubus_object_it, &ubus_object_module_name);
        CHECK_RET_MSG(rc, cleanup, "error getting yang module name");
        if (strncmp(ubus_object_module_name, module_name, strlen(module_name)) == 0)
        {
            ubus_object = ubus_object_it;
            break;
        }
    }

    if (ubus_object == NULL) { return; }
    if (enabled == true)
    {
        rc = ubus_object_libyang_feature_enable(ubus_object, feature_name);
        CHECK_RET_MSG(rc, cleanup, "ubus object libyang enable feature error");
    }
    else
    {
        rc = ubus_object_libyang_feature_disable(ubus_object, feature_name);
        CHECK_RET_MSG(rc, cleanup, "ubus object libyang disable feature error");
    }
cleanup:
    return;
}

/*
 * @brief Callback for gathering ubus state data for a specific ubus YANG module
 *        that is being tracked according to the generic ubus YANG module.
 *
 * @param[in] cb_xpath xpath for the current element.
 * @param[out] values  array of sysrepo values that are set (value anf xpath).
 * @param[out] values_cnt number of values that are set.
 * @param[in] request_id request id for a single module.
 * @param[in] original_xpath original xpath entered by the user.
 * @param[in] private_ctx context beeing passed to the callback.
*/
static int generic_ubus_operational_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    int rc = SR_ERR_OK;
    context_t *context = (context_t *)private_ctx;
    static uint64_t request = 0;
    static ubus_object_t *ubus_object = NULL;
    char *module_name = NULL;
    char *method_name = NULL;
    char *ubus_object_name = NULL;
    char *ubus_message = NULL;
    static char *ubus_method_name = NULL;
    json_object *parsed_json = NULL;
    struct lyd_node *root = NULL;
    struct lyd_node *parent = NULL;
    static struct lys_module *libyang_module = NULL;
    size_t count = 0;
    sr_val_t *sysrepo_values = NULL;
    char *result_json_data = NULL;

    CHECK_NULL_MSG(cb_xpath, &rc, cleanup, "input argument cb_xpath is null");
    CHECK_NULL_MSG(values_cnt, &rc, cleanup, "input argument values_cnt is null");
    CHECK_NULL_MSG(original_xpath, &rc, cleanup, "input argument original_xpath is null");
    CHECK_NULL_MSG(private_ctx, &rc, cleanup, "input argument private_ctx is null");


    *values_cnt = 0;
    if (request != request_id)
    {
        request = request_id;
        ubus_method_name = NULL;

        rc = xpath_get_module_name(cb_xpath, &module_name);
        CHECK_RET_MSG(rc, cleanup, "get module name error");

        ubus_object_t *ubus_object_it = NULL;
        ubus_object = NULL;
        context_for_each_ubus_object(context, ubus_object_it)
        {
            char *yang_module = NULL;
            rc = ubus_object_get_yang_module(ubus_object_it, &yang_module);
            CHECK_RET_MSG(rc, cleanup, "ubus object get yang module error");
            if (strncmp(yang_module, module_name, strlen(module_name)) == 0)
            {
                ubus_object = ubus_object_it;
                break;
            }
        }

        rc = ubus_object_get_libyang_schema(ubus_object, &libyang_module);
        CHECK_RET_MSG(rc, cleanup, "get libyang module schema error");
    }
    else if (ubus_object != NULL)
    {
        rc = xpath_get_module_name(original_xpath, &module_name);
        CHECK_RET_MSG(rc, cleanup, "get module name error");

        rc = ubus_object_get_name(ubus_object, &ubus_object_name);
        CHECK_RET_MSG(rc, cleanup, "get ubus object name error");

        bool skip_ubus_object = false;
        rc = context_filter_ubus_object(context, ubus_object_name, &skip_ubus_object);
        CHECK_RET_MSG(rc, cleanup, "filter ubus object error");

        if (skip_ubus_object == true) { goto cleanup; }

        root = lyd_new(NULL, libyang_module, module_name);
        CHECK_NULL_MSG(root, &rc, cleanup, "libyang data root node");

        rc = xpath_get_tail_node(cb_xpath, &method_name);
        if ( rc == SR_ERR_INTERNAL )
        {
            ERR_MSG("error geting tail node");
        }
        if (rc == -2 || rc == SR_ERR_INTERNAL)
        {
            goto cleanup;
        }

        ubus_method_t *ubus_method_it = NULL;
        ubus_method_t *ubus_method = NULL;
        ubus_object_for_each_ubus_method(ubus_object, ubus_method_it)
        {
            INF("uom_name: %s | uom_message: %s", ubus_method_it->name, ubus_method_it->message);

            rc = ubus_method_get_name(ubus_method_it, &ubus_method_name);
            CHECK_RET_MSG(rc, cleanup, "ubus object get yang module error");

            if (strncmp(ubus_method_name, method_name, strlen(method_name)) == 0)
            {
                ubus_method = ubus_method_it;
                break;
            }
            ubus_method_name = NULL;
        }

        if (ubus_method == NULL)
        {
            INF("method %s not found for object %s", method_name, ubus_object_name);
            rc = SR_ERR_OK;
            goto cleanup;
        }

        rc = ubus_method_get_message(ubus_method, &ubus_message);
        CHECK_RET_MSG(rc, cleanup, "ubus method get method message error");

        result_json_data = NULL;
        rc = ubus_call(ubus_object_name, ubus_method_name, ubus_message, ubus_get_response_cb, &result_json_data);
        CHECK_RET_MSG(rc, cleanup, "ubus call error");

        parsed_json = json_tokener_parse(result_json_data);
        CHECK_NULL_MSG(parsed_json, &rc, cleanup, "tokener parser error");

        parent = lyd_new(root, libyang_module, ubus_method->name);
        CHECK_NULL_MSG(parent, &rc, cleanup, "libyang data root is null");

        rc = generic_ubus_walk_json(parsed_json, libyang_module, parent);
        CHECK_RET_MSG(rc, cleanup, "generic ubus walk json error");

        if (lyd_validate(&root, LYD_OPT_DATA_NO_YANGLIB, NULL) != 0)
        {
            ERR_MSG("error while validating libyang data tree");
            sr_free_val(sysrepo_values);
            goto cleanup;
        }

        rc = generic_ubus_set_sysrepo_data(root, &sysrepo_values, &count);
        if (rc != SR_ERR_OK)
        {
            if (sysrepo_values != NULL) { sr_free_val(sysrepo_values); }
            ERR_MSG("set sysrepo data error");
            goto cleanup;
        }

        *values_cnt = count;
        *values = sysrepo_values;
    }

cleanup:
    free(module_name);
    free(method_name);
    free(result_json_data);

    if (parsed_json != NULL) { json_object_put(parsed_json); }
    if (root != NULL) { lyd_free_withsiblings(root); }

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
        if ( type == json_type_object)
        {
            new_node = lyd_new(node, module, key);
            CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new node error");
            rc = generic_ubus_walk_json(value, module, new_node);
            CHECK_RET_MSG(rc, cleanup, "error while waking tree");
        }
        else if (type == json_type_array)
        {
            size_t json_array_length = json_object_array_length(value);
            for (size_t i = 0; i < json_array_length; i++)
            {
                json_object *entry = json_object_array_get_idx(value, i);
                json_type type = json_object_get_type(entry);
                if (type == json_type_array || type == json_type_object)
                {
                    new_node = lyd_new(node, module, key);
                    CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new node error");
                    rc = generic_ubus_walk_json(entry, module, new_node);
                    CHECK_RET_MSG(rc, cleanup, "error while waking tree");
                }
                else
                {
                    new_node = lyd_new_leaf(node, module, key, json_object_get_string(entry));
                    CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new leaf error");
                }
            }
        }
        else
        {
            new_node = lyd_new_leaf(node, module, key, json_object_get_string(value));
            CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new leaf error");
        }
    }

    return rc;

cleanup:
    if (new_node != NULL) { lyd_free_withsiblings(new_node); }
    return rc;
}

/*
 * @brief Converts the libyang data that has been gatherd from the
 *        JSON data tree to the sysrepo data types and values.
 *
 * @param[in] root root libyang node representing the YANG data tree,
 * @param[out] values sysrepo values to be set.
 * @param[out] values_cnt number of values set.
 *
 * @return error code.
*/
static int generic_ubus_set_sysrepo_data(struct lyd_node *root, sr_val_t **values, size_t *values_cnt)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(root, &rc, cleanup, "input argument root is null");
    CHECK_NULL_MSG(values, &rc, cleanup, "input argument values is null");

    char *node_xpath = NULL;
    struct lyd_node *node = NULL;
    struct lyd_node *next_node = NULL;
    size_t i = 0;
    size_t cnt = 0;
    LY_TREE_DFS_BEGIN(root, next_node, node)
    {

        if (node->schema->nodetype == LYS_LEAF || node->schema->nodetype == LYS_LEAFLIST)
        {
            struct lyd_node_leaf_list *leaf_node = (struct lyd_node_leaf_list *)node;
            if (lys_is_key((const struct lys_node_leaf *)leaf_node->schema, NULL) == NULL)
            {
                cnt++;
            }
        }
        LY_TREE_DFS_END(root, next_node, node)
    }

    rc = sr_new_values(cnt, values);
    SR_CHECK_RET(rc, cleanup, "sr new values error: %s", sr_strerror(rc));

    LY_TREE_DFS_BEGIN(root, next_node, node)
    {

        node_xpath = lyd_path(node);
        CHECK_NULL_MSG(node_xpath, &rc, cleanup, "libyang get xpath error");

        if (node->schema->nodetype == LYS_LEAF || node->schema->nodetype == LYS_LEAFLIST)
        {
            struct lyd_node_leaf_list *leaf_node = (struct lyd_node_leaf_list *)node;
            if (lys_is_key((const struct lys_node_leaf *)leaf_node->schema, NULL) == NULL)
            {
                rc = sr_val_set_xpath(&(*values)[i], node_xpath);
                SR_CHECK_RET(rc, cleanup, "sr set xpath: %s", sr_strerror(rc));

                rc = generic_ubus_libyang_to_sysrepo(leaf_node, &(*values)[i]);
                CHECK_RET_MSG(rc, cleanup, "libyang to sysrepo mapping error");

                i++;
            }
            INF("%s", node_xpath);
        }
        free(node_xpath);
        node_xpath = NULL;
        LY_TREE_DFS_END(root, next_node, node)
    }

    *values_cnt = cnt;
    return rc;


cleanup:
    free(node_xpath);
    *values_cnt = 0;
    return rc;
}

/*
 * @brief Converting libyang data types to sysrepo data types.
 *
 * @param[in] node libyang leaf node that is being converted to sysrepo value.
 * @param[out] value sysrepo value being set from the libyang node.
 *
 * @return error code.
*/
static int generic_ubus_libyang_to_sysrepo(struct lyd_node_leaf_list *node, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(node, &rc, cleanup, "input argument node is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    sr_type_t sr_type;
    uint8_t type_not_set = 1;

    switch(node->value_type)
    {
        case LY_TYPE_BOOL:
            value->type = SR_BOOL_T;
            value->data.bool_val = node->value.bln;
            break;
        case LY_TYPE_DEC64:
            value->type = SR_DECIMAL64_T;
            value->data.decimal64_val = node->value.dec64;
            break;
        case LY_TYPE_EMPTY:
            value->type = SR_LEAF_EMPTY_T;
            break;
        case LY_TYPE_INT8:
            value->type = SR_INT8_T;
            value->data.int8_val = node->value.int8;
            break;
        case LY_TYPE_UINT8:
            value->type = SR_UINT8_T;
            value->data.uint8_val = node->value.uint8;
            break;
        case LY_TYPE_INT16:
            value->type = SR_INT16_T;
            value->data.int16_val = node->value.int16;
            break;
        case LY_TYPE_UINT16:
            value->type = SR_UINT16_T;
            value->data.uint16_val = node->value.uint16;
            break;
        case LY_TYPE_INT32:
            value->type = SR_INT32_T;
            value->data.int32_val = node->value.int32;
            break;
        case LY_TYPE_UINT32:
            value->type = SR_UINT32_T;
            value->data.uint32_val = node->value.uint32;
            break;
        case LY_TYPE_INT64:
            value->type = SR_INT64_T;
            value->data.int64_val = node->value.int64;
            break;
        case LY_TYPE_UINT64:
            value->type = SR_UINT64_T;
            value->data.uint64_val = node->value.uint64;
            break;
        case LY_TYPE_BINARY: // with sr_val_set_str
            sr_type = SR_BINARY_T;
            type_not_set = 0;
        case LY_TYPE_BITS: // with sr_val_set_str
            if (type_not_set == 1) { sr_type = SR_BITS_T; type_not_set = 0; }
        case LY_TYPE_ENUM: // with sr_val_set_str
            if (type_not_set == 1) { sr_type = SR_ENUM_T; type_not_set = 0; }
        case LY_TYPE_IDENT: // with sr_val_set_str
            if (type_not_set == 1) { sr_type = SR_IDENTITYREF_T; type_not_set = 0; }
        case LY_TYPE_INST: // with sr_val_set_str
            if (type_not_set == 1) { sr_type = SR_INSTANCEID_T; type_not_set = 0; }
        case LY_TYPE_STRING: // with sr_val_set_str
            if (type_not_set == 1) { sr_type = SR_STRING_T; type_not_set = 0; }
            rc = sr_val_set_str_data(value, sr_type, node->value_str);
            SR_CHECK_RET(rc, cleanup, "sr set string data error: %s", sr_strerror(rc));
            break;
        case LY_TYPE_UNION:
        case LY_TYPE_LEAFREF:
        case LY_TYPE_DER:
        case LY_TYPE_UNKNOWN:
        default:
            rc = SR_ERR_INTERNAL;
            CHECK_RET_MSG(rc, cleanup, "unsupported type in sysrepo");
    }

cleanup:
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
int generic_ubus_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	context_t *context = (context_t *)private_ctx;

	INF("%d", event);

	if (SR_EV_APPLY == event)
	{
		/* copy running datastore to startup */
        rc = sr_copy_config(context->startup_session, YANG_MODEL, SR_DS_RUNNING, SR_DS_STARTUP);
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
int generic_ubus_ubus_call_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char *tail_node = NULL;
	char *ubus_object_name = NULL;
	char *ubus_method_name = NULL;
	char *ubus_message = NULL;
	sr_val_t *result = NULL;
	size_t count = 0;
	char ubus_invoke_string[256+1] = {0};
	char *result_json_data = NULL;
    context_t *context = (context_t *)private_ctx;
    const char *ubus_object_filtered_out_message = "Ubus object is filtered out";

	*output_cnt = 0;

	INF("%d",input_cnt);

	for (int i = 0; i < input_cnt; i++)
	{
		rc = xpath_get_tail_node(input[i].xpath, &tail_node);
		CHECK_RET_MSG(rc, cleanup, "get tail node error");

		if (strcmp(RPC_UBUS_OBJECT, tail_node) == 0)
		{
			ubus_object_name = input[i].data.string_val;
		}
		else if (strcmp(RPC_UBUS_METHOD, tail_node) == 0)
		{
			ubus_method_name = input[i].data.string_val;
		}
		else if (strcmp(RPC_UBUS_METHOD_MESSAGE, tail_node) == 0)
		{
			ubus_message = input[i].data.string_val;
		}

		uint8_t last = (i + 1) >= input_cnt;

		if ((strstr(tail_node, RPC_UBUS_INVOCATION) != NULL && ubus_method_name != NULL && ubus_object_name != NULL ) || last == 1)
		{
            bool skip_ubus_object = false;
            rc = context_filter_ubus_object(context, ubus_object_name, &skip_ubus_object);
            CHECK_RET_MSG(rc, cleanup, "filter ubus object error");

            INF("%d", skip_ubus_object);
            if (skip_ubus_object == false)
            {
                rc = ubus_call(ubus_object_name, ubus_method_name, ubus_message, ubus_get_response_cb, &result_json_data);
			    CHECK_RET_MSG(rc, cleanup, "ubus call error");
            }
            else
            {
                result_json_data = calloc(1, strlen(ubus_object_filtered_out_message)+1);
                CHECK_NULL_MSG(result_json_data, &rc, cleanup, "result json data alloc error");
                strcpy(result_json_data, ubus_object_filtered_out_message);
            }

			rc = sr_realloc_values(count, count + 2, &result);
			SR_CHECK_RET(rc, cleanup, "sr realloc values error: %s", sr_strerror(rc));

			memset(ubus_invoke_string, 0, 256+1);
			if (ubus_message != NULL)
			{
				snprintf(ubus_invoke_string, 256+1, "%s %s %s", ubus_object_name, ubus_method_name, ubus_message);
			}
			else
			{
				snprintf(ubus_invoke_string, 256+1, "%s %s %s", ubus_object_name, ubus_method_name, JSON_EMPTY_OBJECT);
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

			free(result_json_data);
			result_json_data = NULL;

			count++;
		}
		free(tail_node);
		tail_node = NULL;
	}

	*output_cnt = count;
	*output = result;

	return rc;

cleanup:
	free(tail_node);
	free(result_json_data);
	if (result != NULL) { sr_free_values(result, count); }

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
int generic_ubus_module_install_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
	int rc = SR_ERR_OK;
	int src = 0;
	char *path_to_module = NULL;
	char command[256+1] = {0};
	char return_message[256+1] = {0};
	sr_val_t *return_values = NULL;
	size_t count = 0;

	*output_cnt = 0;
	for (size_t i = 0; i < input_cnt; i++)
	{
		memset(return_message, 0, 256+1);
		memset(command, 0, 256+1);

		path_to_module = input[i].data.string_val;
		INF("%s", path_to_module);

		snprintf(command, 256+1, "sysrepoctl -i -g %s", path_to_module);

		src = system(command);
		if (src == -1)
		{
			ERR("error while executing `system` command: %d", src);
			rc = SR_ERR_INTERNAL;
			goto cleanup;
		}
		else if (src == 0)
		{
			snprintf(return_message, 256+1, "Installation of module %s succeeded", path_to_module);
		}
		else
		{
			snprintf(return_message, 256+1, "Installation of module %s failed, error: %d", path_to_module, src);
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
int generic_ubus_feature_update_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
	int rc = SR_ERR_OK;
	int src = 0;
	char *tail_node = NULL;
	uint8_t enable_feature = 0;
	char *yang_module_name = NULL;
	char *feature_name = NULL;
	sr_val_t *return_values = NULL;
	size_t count = 0;

	char command[256+1] = {0};
	char return_message[256+1] = {0};
	char feature_invoke[256+1] = {0};

	uint8_t make_sysrepoctl_call = 0;
	*output_cnt = 0;
	for (size_t i = 0; i < input_cnt; i++)
	{
		rc = xpath_get_tail_node(input[i].xpath, &tail_node);
		CHECK_RET_MSG(rc, cleanup, "get tail node error");

		if (strcmp("module-name", tail_node) == 0)
		{
			yang_module_name = input[i].data.string_val;
		}
		else if (strcmp("feature-name", tail_node) == 0)
		{
			feature_name = input[i].data.string_val;
		}
		else if (strcmp("enable", tail_node) == 0)
		{
			enable_feature = 1;
			make_sysrepoctl_call = 1;
		}
		else if (strcmp("disable", tail_node) == 0)
		{
			enable_feature = 0;
			make_sysrepoctl_call = 1;
		}

		if (make_sysrepoctl_call == 1)
		{
			memset(feature_invoke, 0, 256+1);
			memset(return_message, 0, 256+1);
			memset(command, 0, 256+1);
			if (enable_feature == 1)
			{
				snprintf(command, 256+1, "sysrepoctl -e %s -m %s", feature_name, yang_module_name);
			}
			else
			{
				snprintf(command, 256+1, "sysrepoctl -d %s -m %s", feature_name, yang_module_name);
			}
			src = system(command);
			if (src == -1)
			{
				ERR("error while executing `system` command: %d", src);
				rc = SR_ERR_INTERNAL;
				goto cleanup;
			}
			else if (src == 0)
			{
				snprintf(return_message, 256+1, "%s feature %s in module %s succeeded.",(enable_feature == 1) ? "Enabeling" : "Disabeling", feature_name, yang_module_name);
			}
			else
			{
				snprintf(return_message, 256+1, "%s feature %s in module %s failed. Error: %d.", (enable_feature == 1) ? "Enabeling" : "Disabeling", feature_name, yang_module_name , src);
			}

			snprintf(feature_invoke, 256+1, "%s %s", yang_module_name, feature_name);


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
		free(tail_node);
		tail_node = NULL;
	}

	*output_cnt = count;
	*output = return_values;

	return rc;

cleanup:
	free(tail_node);
	if (return_values != NULL) { sr_free_values(return_values, count); }
	return rc;
}

