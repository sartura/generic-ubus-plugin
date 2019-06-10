#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "generic_ubus.h"
#include "xpath.h"
#include "sysrepo/values.h"

#include "libyang/tree_data.h"

#define YANG_UBUS_OBJECT "ubus-object"
#define YANG_UBUS_METHOD "method"

enum generic_ubus_operation_e { UBUS_OBJECT_CREATE,
                                UBUS_OBJECT_MODIFY,
                                UBUS_OBJECT_DELETE,
                                UBUS_METHOD_CREATE,
                                UBUS_METHOD_MODIFY,
                                UBUS_METHOD_DELETE,
                                DO_NOTHING };

typedef enum generic_ubus_operation_e generic_ubus_operation_t;

static generic_ubus_operation_t generic_ubus_get_operation(sr_change_oper_t operation, sr_val_t *old_value, sr_val_t *new_value);
static int generic_ubus_create_ubus_object(context_t *context, sr_val_t *value);
static int generic_ubus_modify_ubus_object(context_t *context, sr_val_t *value);
static int generic_ubus_delete_ubus_object(context_t *context, sr_val_t *value);
static int generic_ubus_create_ubus_method(context_t *context, sr_val_t *value);
static int generic_ubus_modify_ubus_method(context_t *context, sr_val_t *value);
static int generic_ubus_delete_ubus_method(context_t *context, sr_val_t *value);
static int generic_ubus_set_context(context_t *context, sr_val_t *value);
static int generic_ubus_operational_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx);
static void ubus_get_response_cb(struct ubus_request *req, int type, struct blob_attr *msg);
static int generic_ubus_walk_json(json_object *object, struct lys_module *module, struct lyd_node *node, size_t *count);
static int generic_ubus_set_sysrepo_data(struct lyd_node *root, sr_val_t **values, size_t *values_cnt);
static int generic_ubus_libyang_to_sysrepo(struct lyd_node_leaf_list *node, sr_val_t *value);

int generic_ubus_load_startup_datastore(context_t *context)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");

    // read from startup
    // if NOT empty set the context
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

int generic_ubus_apply_module_changes(context_t *context, const char *module_name, sr_session_ctx_t *session)
{
    int rc = SR_ERR_OK;
    sr_change_oper_t operation;
    sr_change_iter_t *it = NULL;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    //sr_session_ctx_t *session = context->session;
    char xpath[256+1] = {0};

    snprintf(xpath, strlen(module_name) + 4, "/%s:*", module_name);
    INF("%s", xpath);

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

static generic_ubus_operation_t generic_ubus_get_operation(sr_change_oper_t operation, sr_val_t *old_value, sr_val_t *new_value)
{
    generic_ubus_operation_t plugin_operation = DO_NOTHING;

    // test the ending of the xpath for new_value or old_value
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

    if (operation == SR_OP_CREATED && new_value != NULL && old_value == NULL)
    {
        if (new_value->type == SR_LIST_T)
        {
            if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) { plugin_operation = UBUS_OBJECT_CREATE; }
            else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) { plugin_operation = UBUS_METHOD_CREATE;}
        }
    }
    if ((operation == SR_OP_MODIFIED || operation == SR_OP_CREATED) && new_value != NULL)
    {
        if (new_value->type == SR_STRING_T)
        {
            if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) { plugin_operation = UBUS_OBJECT_MODIFY; }
            else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) { plugin_operation = UBUS_METHOD_MODIFY; }
        }
    }
    if (operation == SR_OP_DELETED && old_value != NULL && new_value ==  NULL)
    {
        if (old_value->type == SR_LIST_T || old_value->type == SR_STRING_T)
        {
            if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) { plugin_operation = UBUS_OBJECT_DELETE; }
            else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) { plugin_operation = UBUS_METHOD_DELETE; }
        }

    }

cleanup:
    free(tail_node);
    return plugin_operation;
}

static int generic_ubus_create_ubus_object(context_t *context, sr_val_t *value)
{
    // create an ubus_object
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    ubus_object_t *ubus_object = NULL;
    rc = ubus_object_create(&ubus_object);
    CHECK_RET_MSG(rc, cleanup, "allocation ubus_object is null");

    // get the name from xpath and set
    char *key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_OBJECT, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    rc = ubus_object_set_name(ubus_object, key);
    CHECK_RET_MSG(rc, cleanup, "set ubus object name error");

    // add to context list
    rc = context_add_ubus_object(context, ubus_object);
    CHECK_RET_MSG(rc, cleanup, "add ubus object to list error");

    free(key);
    return rc;

cleanup:
    ubus_object_destroy(&ubus_object);
    free(key);
    return rc;
}

// if yang module changes unsubscribe from current and subscribe to next
static int generic_ubus_modify_ubus_object(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    // get the name from xpath and set
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

        rc = ubus_object_subscribe(context->session, (void *)context, ubus_object, generic_ubus_operational_cb);
        CHECK_RET_MSG(rc, cleanup, "subscribe error");

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

static int generic_ubus_create_ubus_method(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    // get the name of ubus_object
    char *key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_OBJECT, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    // get the ubus object
    ubus_object_t *ubus_object = NULL;
    rc = context_get_ubus_object(context, &ubus_object, key);
    CHECK_RET_MSG(rc, cleanup, "get ubus object error");

    // get the name of ubus method
    free(key);
    key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_METHOD, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    // create the ubus method
    ubus_method_t *ubus_method = NULL;
    rc = ubus_method_create(&ubus_method);
    CHECK_RET_MSG(rc, cleanup, "allocation ubus_method is null");

    rc = ubus_method_set_name(ubus_method, key);
    CHECK_RET_MSG(rc, cleanup, "set ubus method name error");

    // add the ubus method to ubus object list
    rc = ubus_object_add_method(ubus_object, ubus_method);
    CHECK_RET_MSG(rc, cleanup, "add ubus method to list error");

    free(key);
    return rc;

cleanup:
    ubus_method_destroy(&ubus_method);
    free(key);
    return rc;
}

static int generic_ubus_modify_ubus_method(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    // get the name of ubus_object
    char *key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_OBJECT, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    // get the ubus object
    ubus_object_t *ubus_object = NULL;
    rc = context_get_ubus_object(context, &ubus_object, key);
    CHECK_RET_MSG(rc, cleanup, "get ubus object error");

    // get the name of ubus method
    free(key);
    key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_METHOD, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    // get ubus method
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

static int generic_ubus_delete_ubus_method(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    // get the name of ubus_object
    char *key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_OBJECT, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    // get the ubus object
    ubus_object_t *ubus_object = NULL;
    rc = context_get_ubus_object(context, &ubus_object, key);
    CHECK_RET_MSG(rc, cleanup, "get ubus object error");

    // get the name of ubus method
    free(key);
    key = NULL;
    rc = xpath_get_node_key_value(value->xpath, YANG_UBUS_METHOD, "name", &key);
    CHECK_RET_MSG(rc, cleanup, "allocation key is null");

    // get ubus method
    ubus_method_t *ubus_method = NULL;
    rc = ubus_object_get_method(ubus_object, &ubus_method, key);
    CHECK_RET_MSG(rc, cleanup, "get ubus method error");

    if (value->type == SR_LIST_T)
    {
        rc = ubus_object_delete_method(ubus_object, key);
        CHECK_RET_MSG(rc, cleanup, "delete ubus method error");
    }

cleanup:
    free(key);
    return rc;
}

static int generic_ubus_set_context(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    // check the xpath
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
    else
    {
        // something is wrong or is it tam tam tam
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

static int generic_ubus_operational_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    int rc = SR_ERR_OK;
    int urc = UBUS_STATUS_OK;
    context_t *context = (context_t *)private_ctx;
    static uint64_t request = 0;
    static ubus_object_t *ubus_object = NULL;
    struct ubus_context *ubus_ctx = NULL;
    unsigned int ubus_id = 0;
    char *module_name = NULL;
    char *method_name = NULL;
    static char *ubus_method_name = NULL;
    struct blob_buf buf = {0};
    json_object *parsed_json = NULL;
    struct lyd_node *root = NULL;
    struct lyd_node *parent = NULL;
    static struct lys_module *libyang_module = NULL;
    size_t count = 0;
    sr_val_t *sysrepo_values = NULL;

    CHECK_NULL_MSG(cb_xpath, &rc, cleanup, "input argument cb_xpath is null");
    CHECK_NULL_MSG(values_cnt, &rc, cleanup, "input argument values_cnt is null");
    CHECK_NULL_MSG(original_xpath, &rc, cleanup, "input argument original_xpath is null");
    CHECK_NULL_MSG(private_ctx, &rc, cleanup, "input argument private_ctx is null");


    *values_cnt = 0;
    if (request != request_id)
    {
        request = request_id;
        ubus_method_name = NULL;

        // get the ubus object
        rc = xpath_get_module_name(cb_xpath, &module_name);
        CHECK_RET_MSG(rc, cleanup, "get module name error");

        // go through all ubus objects and find the one with the yang module
        ubus_object_t *ubus_object_it = NULL;
        context_for_each_ubus_object(context, ubus_object_it)
        {

            // compare the requested yang module  and ubus object yang module
            char *yang_module = NULL;
            rc = ubus_object_get_yang_module(ubus_object_it, &yang_module);
            CHECK_RET_MSG(rc, cleanup, "ubus object get yang module error");
            if (strncmp(yang_module, module_name, strlen(yang_module)) == 0)
            {
                ubus_object = ubus_object_it;
                break;
            }
        }
        rc = ubus_object_get_libyang_schema(ubus_object, &libyang_module);
        CHECK_RET_MSG(rc, cleanup, "get libyang module schema error");
    }
    else if (ubus_method_name == NULL)
    {
        rc = xpath_get_module_name(original_xpath, &module_name);
        CHECK_RET_MSG(rc, cleanup, "get module name error");

        root = lyd_new(NULL, libyang_module, module_name);
        CHECK_NULL_MSG(root, &rc, cleanup, "libyang data root node");

        // get the leaf , state data container is required to exists
        rc = xpath_get_tail_node(cb_xpath, &method_name);
        if ( rc == SR_ERR_INTERNAL )
        {
            ERR_MSG("error geting tail node");
        }
        if (rc == -2 || rc == SR_ERR_INTERNAL)
        {
            goto cleanup;
        }

        INF("%s", method_name);

        ubus_method_t *ubus_method_it = NULL;
        ubus_method_t *ubus_method = NULL;
        ubus_object_for_each_ubus_method(ubus_object, ubus_method_it)
        {
            INF("uom_name: %s | uom_message: %s", ubus_method_it->name, ubus_method_it->message);

            char *ubus_method_name = NULL;
            rc = ubus_method_get_name(ubus_method_it, &ubus_method_name);
            CHECK_RET_MSG(rc, cleanup, "ubus object get yang module error");

            if (strncmp(ubus_method_name, method_name, strlen(ubus_method_name)) == 0)
            {
                ubus_method = ubus_method_it;
                break;
            }
        }

        if (ubus_method == NULL)
        {
            rc = SR_ERR_OK;
            goto cleanup;
        }

        rc = ubus_method_get_name(ubus_method, &ubus_method_name);
        CHECK_RET_MSG(rc, cleanup, "ubus method get method name error");

        ubus_ctx = ubus_connect(NULL);
        CHECK_NULL_MSG(ubus_ctx, &rc, cleanup, "ubus context is null");

        urc = ubus_lookup_id(ubus_ctx, ubus_object->name, &ubus_id);
        UBUS_CHECK_RET_MSG(urc, &rc, cleanup, "ubus lookup id error");

        blob_buf_init(&buf, 0);
        blobmsg_add_json_from_string(&buf, ubus_method->message);

        char *result_json_data = NULL;
        urc = ubus_invoke(ubus_ctx, ubus_id, ubus_method->name, buf.head, ubus_get_response_cb, &result_json_data, 1000);
        UBUS_CHECK_RET_MSG(urc, &rc, cleanup, "ubus invoke error");

        rc = ubus_object_set_json_data(ubus_object, result_json_data);
        CHECK_RET_MSG(rc, cleanup, "ubus object set json data error");

        blob_buf_free(&buf);


        char *json_data = NULL;
        rc = ubus_object_get_json_data(ubus_object, &json_data);
        CHECK_RET_MSG(rc, cleanup, "ubus object get json data");

        parsed_json = json_tokener_parse(json_data);
        CHECK_NULL_MSG(parsed_json, &rc, cleanup, "tokener parser error");

        parent = lyd_new(root, libyang_module, ubus_method->name);
        CHECK_NULL_MSG(parent, &rc, cleanup, "libyang data root is null");

        rc = generic_ubus_walk_json(parsed_json, libyang_module, parent, &count);
        CHECK_RET_MSG(rc, cleanup, "generic ubus walk json error");


        // validate the libyang
        if (lyd_validate(&root, LYD_OPT_DATA_NO_YANGLIB, NULL) != 0)
        {
            ERR_MSG("error while validating libyang data tree");
            sr_free_val(sysrepo_values);
            goto cleanup;
        }

        if (count == 0)
        {
            rc = SR_ERR_OK;
            goto cleanup;
        }

        rc = sr_new_values(count, &sysrepo_values);
        SR_CHECK_RET(rc, cleanup, "sr new values error: %s", sr_strerror(rc));

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
    // ubus object and msg blob clean up
    if (ubus_ctx != NULL) {
		ubus_free(ubus_ctx);
	}

    free(module_name);
    free(method_name);

    if (parsed_json != NULL) { json_object_put(parsed_json); }

    blob_buf_free(&buf);

    if (root != NULL) { lyd_free_withsiblings(root); }

    return rc;
}

// TODO: use char as private context
static void ubus_get_response_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{

    if (msg == NULL) {
		return;
	}

    int rc = SR_ERR_OK;
    char **data = req->priv;

    char *result_str = blobmsg_format_json(msg, true);
    CHECK_NULL_MSG(result_str, &rc, cleanup, "json data is null");

    *data = strdup(result_str);

cleanup:
    free(result_str);
    return;
}

static int generic_ubus_walk_json(json_object *object, struct lys_module *module, struct lyd_node *node, size_t *count)
{
    struct lyd_node *new_node = NULL;
    int rc = SR_ERR_OK;

    json_object_object_foreach(object, key, value)
	{
        json_type type = json_object_get_type(value);
        if ( type == json_type_object)
        {
            // create new container node
            new_node = lyd_new(node, module, key);
            CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new node error");
            rc = generic_ubus_walk_json(value, module, new_node, count);
            CHECK_RET_MSG(rc, cleanup, "error while waking tree");
        }
        else if (type == json_type_array)
        {
            CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new node error");
            size_t json_array_length = json_object_array_length(value);
            for (size_t i = 0; i < json_array_length; i++)
            {
                json_object *entry = json_object_array_get_idx(value, i);
                new_node = lyd_new_leaf(node, module, key, json_object_get_string(entry));
                CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new leaf error");
                *count = *count + 1;
            }
        }
        else
        {
            new_node = lyd_new_leaf(node, module, key, json_object_get_string(value));
            CHECK_NULL_MSG(new_node, &rc, cleanup, "libyang data new leaf error");
            *count = *count + 1;
        }
    }

    return rc;

cleanup:
    if (new_node != NULL) { lyd_free_withsiblings(new_node); }
    *count = 0;
    return rc;
}

static int generic_ubus_set_sysrepo_data(struct lyd_node *root, sr_val_t **values, size_t *values_cnt)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(root, &rc, cleanup, "input argument root is null");
    CHECK_NULL_MSG(values, &rc, cleanup, "input argument values is null");
    CHECK_NULL_MSG(values_cnt, &rc, cleanup, "input argument values_cnt is null");

    // go through lyd_nodes and set values and update count
    char *node_xpath = NULL;
    struct lyd_node *node = NULL;
    struct lyd_node *next_node = NULL;
    size_t i = 0;
    LY_TREE_DFS_BEGIN(root, next_node, node)
    {

        node_xpath = lyd_path(node);
        CHECK_NULL_MSG(node_xpath, &rc, cleanup, "libyang get xpath error");

        if (node->schema->nodetype == LYS_LEAF || node->schema->nodetype == LYS_LEAFLIST)
        {
            struct lyd_node_leaf_list *leaf_node = (struct lyd_node_leaf_list *)node;
            rc = sr_val_set_xpath(&(*values)[i], node_xpath);
            SR_CHECK_RET(rc, cleanup, "sr set xpath: %s", sr_strerror(rc));

            rc = generic_ubus_libyang_to_sysrepo(leaf_node, &(*values)[i]);
            CHECK_RET_MSG(rc, cleanup, "libyang to sysrepo mapping error");

            INF("%s", node_xpath);
            i++;
        }
        free(node_xpath);
        node_xpath = NULL;
        LY_TREE_DFS_END(root, next_node, node)
    }

    return rc;


cleanup:
    free(node_xpath);
    return rc;
}

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