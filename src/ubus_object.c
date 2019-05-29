#include "sysrepo.h"

#include "ubus_object.h"

int ubus_object_create(ubus_object_t **ubus_object)
{
    int rc = 0;
    char *name_local = NULL;
    char *yang_module_local = NULL;

//    CHECK_NULL_MSG(name, &rc, cleanup, "input argument name is null");
//    CHECK_NULL_MSG(yang_module, &rc, cleanup, "input argument yang_module is null");

    *ubus_object = calloc(1, sizeof(ubus_object_t));
    CHECK_NULL_MSG(*ubus_object, &rc, cleanup, "return argument ubus_object is null");
/*
    name_local = calloc(strlen(name), sizeof(char));
    CHECK_NULL_MSG(name_local, &rc, cleanup, "memory allocation for name failed");
    yang_module_local = calloc(strlen(yang_module), sizeof(char));
    CHECK_NULL_MSG(yang_module_local, &rc, cleanup, "memory allocation for yang_module failed");

    strncpy(name_local, name, strlen(name_local));
    strncpy(yang_module_local, yang_module, strlen(yang_module_local));
*/
    (*ubus_object)->name = NULL;
    (*ubus_object)->yang_module = NULL;

    INIT_LIST_HEAD(&((*ubus_object)->ubus_method_list));

    return rc;

cleanup:
    free(name_local);
    free(yang_module_local);
    free(ubus_object);
    return rc;
}

int ubus_object_set_name(ubus_object_t *ubus_object, const char *name)
{
    int rc = 0;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(name, &rc, cleanup, "input argument name is null");

    char *name_local = calloc(strlen(name), sizeof(char));
    CHECK_NULL_MSG(name_local, &rc, cleanup, "memory allocation for name failed");

    if (ubus_object->name != NULL) free(ubus_object->name);
    ubus_object->name = name_local;

cleanup:
    return rc;
}

int ubus_object_set_yang_module(ubus_object_t *ubus_object, const char *yang_module)
{
    int rc = 0;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(yang_module, &rc, cleanup, "input argument yang_module is null");

    char *yang_module_local = calloc(strlen(yang_module), sizeof(char));
    CHECK_NULL_MSG(yang_module_local, &rc, cleanup, "memory allocation for yang_module failed");

    if (ubus_object->yang_module != NULL) free(ubus_object->yang_module);
    ubus_object->yang_module = yang_module_local;

cleanup:
    return rc;
}

/*
int ubus_object_subscribe(sr_session_ctx_t *session, void *private_ctx, ubus_object_t *ubus_object, void (*f)())
{
    int rc = 0;
    char *xpath = "/example:state-data"; // will be set with helper function
    // checko input if null
    INF_MSG("Subscribing to operational");
	rc = sr_dp_get_items_subscribe(session,
								   xpath,
								   f, // replace with type definition for state data callback
								   private_ctx,
								   SR_SUBSCR_CTX_REUSE,
								   &ubus_object->state_data_subscription);

	if ( rc != SR_ERR_OK)
    {
        ERR("%s: %s", __func__, sr_strerror(rc));
    }
    return rc;
}
*/
int ubus_object_add_method(ubus_object_t *ubus_object, ubus_method_t *ubus_method)
{
    int rc = 0;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");

    list_add(&ubus_method->list, &ubus_object->ubus_method_list);

cleanup:
    return rc;
}

int ubus_object_delete_method(ubus_object_t *ubus_object, const char *method_name)
{
    int rc = 0;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(method_name, &rc, cleanup, "input argument method_name is null");

    ubus_method_t *ubus_method = NULL;
    rc = ubus_object_get_method(ubus_object, ubus_method, method_name);
    CHECK_RET(rc, cleanup, "ubus method %s not found", method_name);

    list_del(&ubus_method->list);
    ubus_method_destroy(&ubus_method);

cleanup:
    return rc;
}

int ubus_object_delete_all_methods(ubus_object_t *ubus_object)
{
    int rc = 0;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    ubus_method_t *ubus_method_p = NULL;
    ubus_method_t *ubus_method_n = NULL;
    list_for_each_entry_safe(ubus_method_p, ubus_method_n, &ubus_object->ubus_method_list, list)
    {
        list_del(&ubus_method_p->list);
        ubus_method_destroy(&ubus_method_p);
    }

cleanup:
    return rc;
}

int ubus_object_get_name(ubus_object_t *ubus_object, char *name)
{
    int rc = 0;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_object->name, &rc, cleanup, "ubus_object name is null");

    name = ubus_object->name;

cleanup:
    return rc;
}

int ubus_object_get_yang_module(ubus_object_t *ubus_object, char *yang_module)
{
    int rc = 0;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_object->yang_module, &rc, cleanup, "ubus_object yang_module is null");


    yang_module = ubus_object->yang_module;

cleanup:
    return rc;
}

int ubus_object_get_method(ubus_object_t *ubus_object, ubus_method_t *ubus_method, const char *method_name)
{
    int rc = 0;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");

    ubus_method_t *ubus_method_local = NULL;
    list_for_each_entry(ubus_method_local, &ubus_object->ubus_method_list, list)
    {
        if (strncmp(ubus_method_local->name, method_name, strlen(ubus_method_local->name)) == 0)
        {
            ubus_method = ubus_method_local;
            return rc;
        }
    }
    ERR("method %s not found", method_name);
    rc = SR_ERR_INTERNAL;

cleanup:
    return rc;
}

int ubus_object_unsubscribe(sr_session_ctx_t *session, ubus_object_t *ubus_object)
{
    int rc = 0;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_object->state_data_subscription, &rc, cleanup, "state_data_subscription is null");
    CHECK_NULL_MSG(session, &rc, cleanup, "input argument session is null");

    rc = sr_unsubscribe(session, ubus_object->state_data_subscription);
    SR_CHECK_RET(rc, cleanup, "sr_unsubscribe: %s", sr_strerror(rc));

cleanup:
    return rc;
}

void ubus_object_destroy(ubus_object_t **ubus_object)
{
    if (*ubus_object != NULL)
    {
        free((*ubus_object)->name);
        free((*ubus_object)->yang_module);
        int rc = ubus_object_delete_all_methods(*ubus_object);
        CHECK_RET_MSG(rc , cleanup, "ubus object delete all methods error");
    }
cleanup:
    free(*ubus_object);
    *ubus_object = NULL;
}