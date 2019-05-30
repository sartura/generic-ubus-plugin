#include "generic_ubus.h"
#include "xpath.h"
#include "sysrepo/values.h"

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

// TODO: add ubus_object_name and ubus_method name to be set by function
// TODO: or separate functions to be called for getting the name from xpath
static generic_ubus_operation_t generic_ubus_get_operation(sr_change_oper_t operation, sr_val_t *old_value, sr_val_t *new_value);
static int generic_ubus_create_ubus_object(context_t *context, sr_val_t *value);
static int generic_ubus_modify_ubus_object(context_t *context, sr_val_t *value);
static int generic_ubus_delete_ubus_object(context_t *context, sr_val_t *value);

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
                INF_MSG("create!!!!!!!!!!!");
                rc = generic_ubus_create_ubus_object(context, new_value);
                CHECK_RET_MSG(rc, cleanup, "error while creating ubus_object");
                break;
            case UBUS_OBJECT_MODIFY:
                INF_MSG("modify!!!!!!!!!!!");
                rc = generic_ubus_modify_ubus_object(context, new_value);
                CHECK_RET_MSG(rc, cleanup, "error while creating ubus_object");
                break;
            case UBUS_OBJECT_DELETE:
                rc = generic_ubus_delete_ubus_object(context, old_value);
                INF_MSG("delete!!!!!!!!!!!");
                CHECK_RET_MSG(rc, cleanup, "error while creating ubus_object");
                break;
            case UBUS_METHOD_CREATE: break;
            case UBUS_METHOD_MODIFY: break;
            case UBUS_METHOD_DELETE: break;
            default: break;
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
    char *node_name = NULL;
    const char *xpath = (new_value != NULL) ? new_value->xpath : ((old_value != NULL) ? old_value->xpath : NULL);
    int rc = 0;
    INF("%s", xpath);
    rc = xpath_get_list_node(xpath, &tail_node);
    if (rc == SR_ERR_INTERNAL)
    {
        ERR_MSG("xpath_get_tail_node error");
        goto cleanup;
    }
    // CHECK_RET_MSG(rc, cleanup, "xpath_get_tail_node error");

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
        if (old_value->type == SR_LIST_T)
        {
            if (strcmp(tail_node, YANG_UBUS_OBJECT) == 0) { plugin_operation = UBUS_OBJECT_DELETE; }
            else if (strcmp(tail_node, YANG_UBUS_METHOD) == 0) { plugin_operation = UBUS_METHOD_DELETE; }
        }
    }

cleanup:
    free(tail_node);
    free(node_name);
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
    char *attr = NULL;
    rc = xpath_get_last_list_attribute_name(value->xpath, &attr);
    CHECK_RET_MSG(rc, cleanup, "allocation attr is null");

    rc = ubus_object_set_name(ubus_object, attr);
    CHECK_RET_MSG(rc, cleanup, "set ubus object name error");

    // add to context list
    rc = context_add_ubus_object(context, ubus_object);
    CHECK_RET_MSG(rc, cleanup, "add ubus object to list error");

    free(attr);
    return rc;

cleanup:
    ubus_object_destroy(&ubus_object);
    free(attr);
    return rc;
}

static int generic_ubus_modify_ubus_object(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    // get the name from xpath and set
    char *attr = NULL;
    rc = xpath_get_last_list_attribute_name(value->xpath, &attr);
    CHECK_RET_MSG(rc, cleanup, "allocation attr is null");

    ubus_object_t *ubus_object = NULL;
    rc = context_get_ubus_object(context, &ubus_object, attr);
    CHECK_RET_MSG(rc, cleanup, "get ubus object error");

    char *leaf = NULL;
    xpath_get_list_node(value->xpath, &leaf);
    if (strcmp("yang_module", leaf) == 0)
    {
        rc = ubus_object_set_yang_module(ubus_object, value->data.string_val);
        CHECK_RET_MSG(rc, cleanup, "set ubus object yang module error");
    }
    /*
    if (strcmp("name", leaf) == 0)
    {
        rc = ubus_object_set_name(ubus_object, value->data.string_val);
        CHECK_RET_MSG(rc, cleanup, "set ubus object name error");
    }
    */

cleanup:
    free(attr);
    free(leaf);
    return rc;
}

static int generic_ubus_delete_ubus_object(context_t *context, sr_val_t *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(value, &rc, cleanup, "input argument value is null");

    INF("%s",value->xpath);

    char *attr = NULL;
    rc = xpath_get_last_list_attribute_name(value->xpath, &attr);
    CHECK_RET_MSG(rc, cleanup, "allocation attr is null");

    INF("%s",attr);

    if (value->type == SR_LIST_T)
    {
        rc = context_delete_ubus_object(context, attr);
        CHECK_RET_MSG(rc, cleanup, "delete ubus object error");
    }
    // name and yang module can't be deleted they are mandatory
    // they can only be modified

cleanup:
    free(attr);
    return rc;
}