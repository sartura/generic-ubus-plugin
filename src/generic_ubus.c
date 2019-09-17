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
generic_ubus_get_operation(sr_change_oper_t operation, sr_val_t *old_value,
                           sr_val_t *new_value);
static int generic_ubus_create_ubus_object(context_t *context, sr_val_t *value);
static int generic_ubus_modify_ubus_object(context_t *context, sr_val_t *value);
static int generic_ubus_delete_ubus_object(context_t *context, sr_val_t *value);
static int generic_ubus_update_filter(context_t *context, sr_val_t *value);
static int generic_ubus_create_ubus_method(context_t *context, sr_val_t *value);
static int generic_ubus_modify_ubus_method(context_t *context, sr_val_t *value);
static int generic_ubus_delete_ubus_method(context_t *context, sr_val_t *value);
static int generic_ubus_set_context(context_t *context, sr_val_t *value);
static int
generic_ubus_operational_cb(sr_session_ctx_t *session, const char *module_name,
                            const char *path, const char *request_xpath,
                            uint32_t request_id, struct lyd_node **parent,
                            void *private_data);
static int generic_ubus_walk_json(json_object *object,
                                  struct lys_module *module,
                                  struct lyd_node *node);
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
int generic_ubus_load_startup_datastore(context_t *context) {
  int rc = SR_ERR_OK;
  CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");

  sr_val_t *values = NULL;
  size_t count = 0;
  char *xpath = "/" YANG_MODEL ":generic-ubus-config//*";

  rc = sr_get_items(context->startup_session, xpath, &values, &count);
  if (SR_ERR_NOT_FOUND == rc) {
    INF_MSG("empty startup datastore for context data");
    return SR_ERR_OK;
  } else if (SR_ERR_OK != rc) {
    goto cleanup;
  }

  INF("setting context data: %d", count);
  for (size_t i = 0; i < count; i++) {
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
int generic_ubus_apply_module_changes(context_t *context,
                                      const char *module_name,
                                      sr_session_ctx_t *session) {
  int rc = SR_ERR_OK;
  sr_change_oper_t operation;
  sr_change_iter_t *it = NULL;
  sr_val_t *old_value = NULL;
  sr_val_t *new_value = NULL;

  char xpath[256 + 1] = {0};

  snprintf(xpath, strlen(module_name) + 7, "/%s:*//.", module_name);

  rc = sr_get_changes_iter(session, xpath, &it);
  SR_CHECK_RET(rc, cleanup, "sr_get_change_iter: %s", sr_strerror(rc));

  while (1) {
    int cont =
        sr_get_change_next(session, it, &operation, &old_value, &new_value);
    if (cont != SR_ERR_OK) {
      break;
    }

    generic_ubus_operation_t plugin_operation =
        generic_ubus_get_operation(operation, old_value, new_value);

    switch (plugin_operation) {
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
  if (old_value != NULL) {
    sr_free_val(old_value);
  }
  if (new_value != NULL) {
    sr_free_val(new_value);
  }
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
generic_ubus_get_operation(sr_change_oper_t operation, sr_val_t *old_value,
                           sr_val_t *new_value) {
  generic_ubus_operation_t plugin_operation = DO_NOTHING;

  char *tail_node = NULL;
  const char *xpath = (new_value != NULL)
                          ? new_value->xpath
                          : ((old_value != NULL) ? old_value->xpath : NULL);
  int rc = 0;
  INF("%s", xpath);
  rc = xpath_get_tail_list_node(xpath, &tail_node);
  if (rc == SR_ERR_INTERNAL) {
    ERR_MSG("xpath get tail list node error");
    goto cleanup;
  } else if (rc == -2) {
    rc = xpath_get_tail_node(xpath, &tail_node);
    if (rc == SR_ERR_INTERNAL) {
      ERR_MSG("xpath get tail list node error");
      goto cleanup;
    }
  }

  if (operation == SR_OP_CREATED && new_value != NULL && old_value == NULL) {
    if (new_value->type == SR_LIST_T) {
      if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) {
        plugin_operation = UBUS_OBJECT_CREATE;
      } else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) {
        plugin_operation = UBUS_METHOD_CREATE;
      }
    } else if (new_value->type == SR_STRING_T) {
      if (strcmp(tail_node, YANG_UBUS_FILTER) == 0) {
        plugin_operation = UBUS_FILTER_CREATE;
      }
    }
  }
  if ((operation == SR_OP_MODIFIED || operation == SR_OP_CREATED) &&
      new_value != NULL) {
    if (new_value->type == SR_STRING_T) {
      if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) {
        plugin_operation = UBUS_OBJECT_MODIFY;
      } else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) {
        plugin_operation = UBUS_METHOD_MODIFY;
      } else if (strcmp(tail_node, YANG_UBUS_FILTER) == 0) {
        plugin_operation = UBUS_FILTER_MODIFY;
      }
    }
  }
  if (operation == SR_OP_DELETED && old_value != NULL && new_value == NULL) {
    if (old_value->type == SR_LIST_T || old_value->type == SR_STRING_T) {
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
static int generic_ubus_create_ubus_object(context_t *context,
                                           sr_val_t *value) {
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
static int generic_ubus_modify_ubus_object(context_t *context,
                                           sr_val_t *value) {
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

  if (strcmp("yang-module", leaf) == 0) {
    rc = ubus_object_unsubscribe(context->session, ubus_object);
    CHECK_RET_MSG(rc, cleanup, "unsubscribe error");

    rc = ubus_object_set_yang_module(ubus_object, value->data.string_val);
    CHECK_RET_MSG(rc, cleanup, "set ubus object yang module error");

    rc = ubus_object_state_data_subscribe(context->session, (void *)context,
                                          ubus_object,
                                          generic_ubus_operational_cb);
    CHECK_RET_MSG(rc, cleanup, "module change subscribe error");
    /*
        rc = ubus_object_init_libyang_data(ubus_object, context->session);
        CHECK_RET_MSG(rc, cleanup, "init libyang context error");
    */
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
static int generic_ubus_delete_ubus_object(context_t *context,
                                           sr_val_t *value) {
  int rc = SR_ERR_OK;
  CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
  CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

  char *key = NULL;
  rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_OBJECT, "name", &key);
  CHECK_RET_MSG(rc, cleanup, "allocation key is null");

  if (value->type == SR_LIST_T) {
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
static int generic_ubus_create_ubus_method(context_t *context,
                                           sr_val_t *value) {
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
static int generic_ubus_modify_ubus_method(context_t *context,
                                           sr_val_t *value) {
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
  if (strcmp("message", leaf) == 0) {
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
static int generic_ubus_delete_ubus_method(context_t *context,
                                           sr_val_t *value) {
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

  if (value->type == SR_LIST_T) {
    rc = ubus_object_delete_method(ubus_object, key);
    CHECK_RET_MSG(rc, cleanup, "delete ubus method error");
  } else if (value->type == SR_STRING_T) {
    rc = xpath_get_tail_node(value->xpath, &leaf);
    CHECK_RET_MSG(rc, cleanup, "xpath get tail node");
    if (strcmp("message", leaf) == 0) {
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
static int generic_ubus_update_filter(context_t *context, sr_val_t *value) {
  int rc = SR_ERR_OK;
  CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");

  char *data = NULL;

  if (value != NULL) {
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
static int generic_ubus_set_context(context_t *context, sr_val_t *value) {
  int rc = SR_ERR_OK;
  CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
  CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

  char *tail_node = NULL;
  char *key = NULL;
  rc = xpath_get_tail_node(value->xpath, &tail_node);
  CHECK_RET_MSG(rc, cleanup, "xpath get tail node");

  INF("%s", value->xpath);

  if (strncmp(YANG_UBUS_OBJECT, tail_node, strlen(YANG_UBUS_OBJECT)) == 0 &&
      value->type == SR_LIST_T) {
    INF_MSG("create ubus object");
    rc = generic_ubus_create_ubus_object(context, value);
    CHECK_RET_MSG(rc, cleanup, "create ubus object error");
  } else if (strncmp(YANG_UBUS_METHOD, tail_node, strlen(YANG_UBUS_METHOD)) ==
                 0 &&
             value->type == SR_LIST_T) {
    INF_MSG("create ubus method");
    rc = generic_ubus_create_ubus_method(context, value);
    CHECK_RET_MSG(rc, cleanup, "create ubus method error");
  } else if (strncmp(tail_node, "yang-module", strlen(tail_node)) == 0 &&
             value->type == SR_STRING_T) {
    INF_MSG("modifying ubus object");
    rc = generic_ubus_modify_ubus_object(context, value);
    CHECK_RET_MSG(rc, cleanup, "modify ubus object error");
  } else if (strncmp(tail_node, "message", strlen(tail_node)) == 0 &&
             value->type == SR_STRING_T) {
    INF_MSG("modify ubus method");
    rc = generic_ubus_modify_ubus_method(context, value);
    CHECK_RET_MSG(rc, cleanup, "modify ubus method error");
  } else if (strncmp(tail_node, YANG_UBUS_FILTER, strlen(tail_node)) == 0 &&
             value->type == SR_STRING_T) {
    INF_MSG("modify ubus object fitler");
    rc = generic_ubus_update_filter(context, value);
    CHECK_RET_MSG(rc, cleanup, "modify ubus object filter error");
  } else {
    INF_MSG("ignoring the sysrepo value");
  }

  free(key);
  free(tail_node);
  return rc;

cleanup:
  free(key);
  free(tail_node);

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
                            void *private_data) {

  /*
  int rc = SR_ERR_OK;
  context_t *context = (context_t *)private_data;
  static uint64_t request = 0;
  static ubus_object_t *ubus_object = NULL;
  char *method_name = NULL;
  char *ubus_object_name = NULL;
  char *ubus_message = NULL;
  static char *ubus_method_name = NULL;
  json_object *parsed_json = NULL;
  struct lyd_node *root = NULL;
  struct lyd_node *root_child = NULL;
  static struct lys_module *libyang_module = NULL;
  sr_val_t *sysrepo_values = NULL;
  char *result_json_data = NULL;
  sr_conn_ctx_t *connection = NULL;
  const struct ly_ctx *libyang_context = NULL;

  CHECK_NULL_MSG(path, &rc, cleanup, "input argument cb_xpath is null");
  CHECK_NULL_MSG(private_data, &rc, cleanup,
                 "input argument private_ctx is null");

  INF("%s", path);
  INF("%s", request_xpath);

  if (request != request_id) {
    request = request_id;
    ubus_method_name = NULL;

    ubus_object_t *ubus_object_it = NULL;
    ubus_object = NULL;
    context_for_each_ubus_object(context, ubus_object_it) {
      char *yang_module = NULL;
      rc = ubus_object_get_yang_module(ubus_object_it, &yang_module);
      CHECK_RET_MSG(rc, cleanup, "ubus object get yang module error");
      INF("yang_module: %s module_name: %s", yang_module, module_name);
      if (strncmp(yang_module, module_name, strlen(module_name)) == 0) {
        INF_MSG("Tu sam prvi put");
        ubus_object = ubus_object_it;
        break;
      }
    }

    connection = sr_session_get_connection(session);
    CHECK_NULL_MSG(connection, &rc, cleanup, "sr_session_get_connection error");

    libyang_context = sr_get_context(connection);
    CHECK_NULL_MSG(libyang_context, &rc, cleanup, "sr_get_context error");

    libyang_module = (struct lys_module *)ly_ctx_get_module(
        libyang_context, module_name, NULL, 1);
    CHECK_NULL_MSG(libyang_module, &rc, cleanup, "ly_ctx_get_module error");

  } else if (ubus_object != NULL) {
    rc = ubus_object_get_name(ubus_object, &ubus_object_name);
    CHECK_RET_MSG(rc, cleanup, "get ubus object name error");

    bool skip_ubus_object = false;
    rc = context_filter_ubus_object(context, ubus_object_name,
                                    &skip_ubus_object);
    CHECK_RET_MSG(rc, cleanup, "filter ubus object error");

    if (skip_ubus_object == true) {
      goto cleanup;
    }

    root = lyd_new(NULL, libyang_module, module_name);
    CHECK_NULL_MSG(root, &rc, cleanup, "libyang data root node");

    rc = xpath_get_tail_node(path, &method_name);
    if (rc == SR_ERR_INTERNAL) {
      ERR_MSG("error geting tail node");
    }
    if (rc == -2 || rc == SR_ERR_INTERNAL) {
      goto cleanup;
    }

    ubus_method_t *ubus_method_it = NULL;
    ubus_method_t *ubus_method = NULL;
    ubus_object_for_each_ubus_method(ubus_object, ubus_method_it) {
      INF("uom_name: %s | uom_message: %s", ubus_method_it->name,
          ubus_method_it->message);

      rc = ubus_method_get_name(ubus_method_it, &ubus_method_name);
      CHECK_RET_MSG(rc, cleanup, "ubus object get yang module error");

      if (strncmp(ubus_method_name, method_name, strlen(method_name)) == 0) {
        ubus_method = ubus_method_it;
        break;
      }
      ubus_method_name = NULL;
    }

    if (ubus_method == NULL) {
      INF("method %s not found for object %s", method_name, ubus_object_name);
      rc = SR_ERR_OK;
      goto cleanup;
    }

    rc = ubus_method_get_message(ubus_method, &ubus_message);
    CHECK_RET_MSG(rc, cleanup, "ubus method get method message error");

    result_json_data = NULL;
    rc = ubus_call(ubus_object_name, ubus_method_name, ubus_message,
                   ubus_get_response_cb, &result_json_data);
    CHECK_RET_MSG(rc, cleanup, "ubus call error");

    parsed_json = json_tokener_parse(result_json_data);
    CHECK_NULL_MSG(parsed_json, &rc, cleanup, "tokener parser error");

    root_child = lyd_new(root, libyang_module, ubus_method->name);
    CHECK_NULL_MSG(root_child, &rc, cleanup, "libyang data root is null");

    rc = generic_ubus_walk_json(parsed_json, libyang_module, root_child);
    CHECK_RET_MSG(rc, cleanup, "generic ubus walk json error");

    if (lyd_validate(&root, LYD_OPT_DATA_NO_YANGLIB, NULL) != 0) {
      ERR_MSG("error while validating libyang data tree");
      sr_free_val(sysrepo_values);
      goto cleanup;
    }

    *parent = root;
    INF_MSG("Tu sam");
  }

cleanup:
  free(method_name);
  free(result_json_data);

  if (parsed_json != NULL) {
    json_object_put(parsed_json);
  }

  return rc;
*/
  int rc = SR_ERR_OK;
  char module_whole[256] = {0};
  ubus_object_t *ubus_object_iterator = NULL;
  ubus_method_t *ubus_method_iterator = NULL;
  ubus_object_t *ubus_object = NULL;
  char *ubus_object_name = NULL;
  context_t *context = (context_t *)private_data;
  char *xpath_method_name = NULL;
  char *result_json_data = NULL;
  json_object *parsed_json = NULL;
  struct lyd_node *root = NULL;
  struct lyd_node *root_child = NULL;
  static struct lys_module *libyang_module = NULL;
  sr_conn_ctx_t *connection = NULL;
  const struct ly_ctx *libyang_context = NULL;

  CHECK_NULL_MSG(path, &rc, cleanup, "input argument cb_xpath is null");
  CHECK_NULL_MSG(private_data, &rc, cleanup,
                 "input argument private_ctx is null");

  INF("%s", path);

  context_for_each_ubus_object(context, ubus_object_iterator) {
    char *ubus_object_module_name = NULL;
    rc = ubus_object_get_yang_module(ubus_object_iterator,
                                     &ubus_object_module_name);
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

  libyang_module = (struct lys_module *)ly_ctx_get_module(libyang_context,
                                                          module_name, NULL, 1);
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

  ubus_object_for_each_ubus_method(ubus_object, ubus_method_iterator) {
    char *ubus_method_name = NULL;
    rc = ubus_method_get_name(ubus_method_iterator, &ubus_method_name);
    CHECK_RET_MSG(rc, cleanup, "ubus method get name error");

    if ((xpath_method_name &&
         (strcmp(xpath_method_name, ubus_method_name) == 0)) ||
        xpath_method_name == NULL) {

      char *ubus_message = NULL;
      rc = ubus_method_get_message(ubus_method_iterator, &ubus_message);
      CHECK_RET_MSG(rc, cleanup, "ubus method get method message error");

      result_json_data = NULL;
      rc = ubus_call(ubus_object_name, ubus_method_name, ubus_message,
                     ubus_get_response_cb, &result_json_data);
      CHECK_RET_MSG(rc, cleanup, "ubus call error");

      parsed_json = json_tokener_parse(result_json_data);
      CHECK_NULL_MSG(parsed_json, &rc, cleanup, "tokener parser error");

      root_child = lyd_new(root, libyang_module, ubus_method_name);
      CHECK_NULL_MSG(root_child, &rc, cleanup, "libyang data root is null");

      rc = generic_ubus_walk_json(parsed_json, libyang_module, root_child);
      CHECK_RET_MSG(rc, cleanup, "generic ubus walk json error");

      *parent = root;

      free(result_json_data);
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

  free(xpath_method_name);

  return rc;

cleanup:
  free(xpath_method_name);
  free(result_json_data);

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
static int generic_ubus_walk_json(json_object *object,
                                  struct lys_module *module,
                                  struct lyd_node *node) {
  struct lyd_node *new_node = NULL;
  int rc = SR_ERR_OK;

  json_object_object_foreach(object, key, value) {
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
          new_node =
              lyd_new_leaf(node, module, key, json_object_get_string(entry));
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
                           const char *xpath, sr_event_t event,
                           uint32_t request_id, void *private_data) {
  int rc = SR_ERR_OK;
  context_t *context = (context_t *)private_data;

  INF("%d", event);

  if (SR_EV_DONE == event) {
    /* copy running datastore to startup */
    rc = sr_copy_config(context->startup_session, YANG_MODEL, SR_DS_RUNNING,
                        SR_DS_STARTUP);
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
int generic_ubus_ubus_call_rpc_cb(sr_session_ctx_t *session,
                                  const char *op_path, const sr_val_t *input,
                                  const size_t input_cnt, sr_event_t event,
                                  uint32_t request_id, sr_val_t **output,
                                  size_t *output_cnt, void *private_data) {
  int rc = SR_ERR_OK;
  char *tail_node = NULL;
  char *ubus_object_name = NULL;
  char *ubus_method_name = NULL;
  char *ubus_message = NULL;
  sr_val_t *result = NULL;
  size_t count = 0;
  char ubus_invoke_string[256 + 1] = {0};
  char *result_json_data = NULL;
  context_t *context = (context_t *)private_data;
  const char *ubus_object_filtered_out_message = "Ubus object is filtered out";

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
      rc = context_filter_ubus_object(context, ubus_object_name,
                                      &skip_ubus_object);
      CHECK_RET_MSG(rc, cleanup, "filter ubus object error");

      INF("%d", skip_ubus_object);
      if (skip_ubus_object == false) {
        rc = ubus_call(ubus_object_name, ubus_method_name, ubus_message,
                       ubus_get_response_cb, &result_json_data);
        CHECK_RET_MSG(rc, cleanup, "ubus call error");
      } else {
        result_json_data =
            calloc(1, strlen(ubus_object_filtered_out_message) + 1);
        CHECK_NULL_MSG(result_json_data, &rc, cleanup,
                       "result json data alloc error");
        strcpy(result_json_data, ubus_object_filtered_out_message);
      }

      rc = sr_realloc_values(count, count + 2, &result);
      SR_CHECK_RET(rc, cleanup, "sr realloc values error: %s", sr_strerror(rc));

      memset(ubus_invoke_string, 0, 256 + 1);
      if (ubus_message != NULL) {
        snprintf(ubus_invoke_string, 256 + 1, "%s %s %s", ubus_object_name,
                 ubus_method_name, ubus_message);
      } else {
        snprintf(ubus_invoke_string, 256 + 1, "%s %s %s", ubus_object_name,
                 ubus_method_name, JSON_EMPTY_OBJECT);
      }

      rc = sr_val_build_xpath(&result[count], RPC_UBUS_INVOCATION_XPATH,
                              ubus_invoke_string);
      SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

      rc = sr_val_set_str_data(&result[count], SR_STRING_T, ubus_invoke_string);
      SR_CHECK_RET(rc, cleanup, "sr value set str data: %s", sr_strerror(rc));

      count++;

      rc = sr_val_build_xpath(&result[count], RPC_UBUS_RESPONSE_XPATH,
                              ubus_invoke_string);
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
int generic_ubus_module_install_rpc_cb(sr_session_ctx_t *session,
                                       const char *op_path,
                                       const sr_val_t *input,
                                       const size_t input_cnt, sr_event_t event,
                                       uint32_t request_id, sr_val_t **output,
                                       size_t *output_cnt, void *private_data) {
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
      snprintf(return_message, 256 + 1, "Installation of module %s succeeded",
               path_to_module);
    } else {
      snprintf(return_message, 256 + 1,
               "Installation of module %s failed, error: %d", path_to_module,
               src);
    }
    rc = sr_realloc_values(count, count + 2, &return_values);
    SR_CHECK_RET(rc, cleanup, "sr new values error: %s", sr_strerror(rc));

    rc = sr_val_build_xpath(&return_values[count], RPC_MODULE_PATH_XPATH,
                            path_to_module);
    SR_CHECK_RET(rc, cleanup, "sr set xpath for value error: %s",
                 sr_strerror(rc));

    rc =
        sr_val_set_str_data(&return_values[count], SR_STRING_T, path_to_module);
    SR_CHECK_RET(rc, cleanup, "sr set string value error: %s", sr_strerror(rc));

    count++;

    rc = sr_val_build_xpath(&return_values[count], RPC_MODULE_RESPONSE_XPATH,
                            path_to_module);
    SR_CHECK_RET(rc, cleanup, "sr set xpath for value error: %s",
                 sr_strerror(rc));

    rc =
        sr_val_set_str_data(&return_values[count], SR_STRING_T, return_message);
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
                                 const size_t values_cnt, time_t timestamp,
                                 void *private_data) {}

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
int generic_ubus_feature_update_rpc_cb(sr_session_ctx_t *session,
                                       const char *op_path,
                                       const sr_val_t *input,
                                       const size_t input_cnt, sr_event_t event,
                                       uint32_t request_id, sr_val_t **output,
                                       size_t *output_cnt, void *private_data) {
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
        snprintf(return_message, 256 + 1,
                 "%s feature %s in module %s succeeded.",
                 (enable_feature == 1) ? "Enabeling" : "Disabeling",
                 feature_name, yang_module_name);
      } else {
        snprintf(return_message, 256 + 1,
                 "%s feature %s in module %s failed. Error: %d.",
                 (enable_feature == 1) ? "Enabeling" : "Disabeling",
                 feature_name, yang_module_name, src);
      }

      snprintf(feature_invoke, 256 + 1, "%s %s", yang_module_name,
               feature_name);

      rc = sr_realloc_values(count, count + 2, &return_values);
      SR_CHECK_RET(rc, cleanup, "sr realloc values error: %s", sr_strerror(rc));

      rc = sr_val_build_xpath(&return_values[count],
                              RPC_FEATURE_INVOCATION_XPATH, feature_invoke);
      SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

      rc = sr_val_set_str_data(&return_values[count], SR_STRING_T,
                               feature_invoke);
      SR_CHECK_RET(rc, cleanup, "sr value set str data: %s", sr_strerror(rc));

      count++;

      rc = sr_val_build_xpath(&return_values[count], RPC_FEATURE_RESPONSE_XPATH,
                              feature_invoke);
      SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

      rc = sr_val_set_str_data(&return_values[count], SR_STRING_T,
                               return_message);
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
  if (return_values != NULL) {
    sr_free_values(return_values, count);
  }
  return rc;
}
