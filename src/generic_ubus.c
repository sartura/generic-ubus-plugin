#include "generic_ubus.h"

enum generic_ubus_operation_e { UBUS_OBJECT_CREATE,
                                UBUS_OBJECT_MODIFY,
                                UBUS_OBJECT_DELETE,
                                UBUS_METHOD_CREATE,
                                UBUS_METHOD_MODIFY,
                                UBUS_METHOD_DELETE };

typedef enum generic_ubus_operation_e generic_ubus_operation_t;

// TODO: add ubus_object_name and ubus_method name to be set by function
// TODO: or separate functions to be called for getting the name from xpath
static generic_ubus_operation_t generic_ubus_get_operation(sr_change_oper_t operation, sr_val_t *old_value, sr_val_t *new_value);

int generic_ubus_apply_module_changes(context_t *context, const char *module_name)
{
    int rc = SR_ERR_OK;
    sr_change_oper_t operation;
    sr_change_iter_t *it = NULL;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    sr_session_ctx_t *session = context->session;
    char xpath[256+1] = {0};

    snprintf(xpath, strlen(module_name) + 4, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, xpath, &it);
    SR_CHECK_RET(rc, cleanup, "sr_get_change_iter: %s", sr_strerror(rc));

    while (1)
    {
        rc = sr_get_change_next(session, it, &operation, &old_value, &new_value);
        if (rc != SR_ERR_OK) { break; }

        generic_ubus_operation_t plugin_operation = generic_ubus_get_operation(operation, old_value, new_value);

        switch(plugin_operation)
        {
            case UBUS_OBJECT_CREATE:

                break;
            case UBUS_OBJECT_MODIFY: break;
            case UBUS_OBJECT_DELETE: break;
            case UBUS_METHOD_CREATE: break;
            case UBUS_METHOD_MODIFY: break;
            case UBUS_METHOD_DELETE: break;
            default: break;
        }

    }

cleanup:
    if (it != NULL) { sr_free_change_iter(it); }
    return rc;
}

static generic_ubus_operation_t generic_ubus_get_operation(sr_change_oper_t operation, sr_val_t *old_value, sr_val_t *new_value)
{
    return UBUS_METHOD_MODIFY;
}