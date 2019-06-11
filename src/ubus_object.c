#include "sysrepo.h"

#include "ubus_object.h"

int ubus_object_create(ubus_object_t **ubus_object)
{
    int rc = SR_ERR_OK;

    *ubus_object = calloc(1, sizeof(ubus_object_t));
    CHECK_NULL_MSG(*ubus_object, &rc, cleanup, "return argument ubus_object is null");

    (*ubus_object)->name = NULL;
    (*ubus_object)->yang_module = NULL;
    (*ubus_object)->state_data_subscription = NULL;

    (*ubus_object)->libyang_ctx = NULL;
    (*ubus_object)->libyang_module = NULL;

    INIT_LIST_HEAD(&((*ubus_object)->ubus_method_list));

    return rc;

cleanup:
    free(ubus_object);
    return rc;
}

int ubus_object_set_name(ubus_object_t *ubus_object, const char *name)
{
    int rc = SR_ERR_OK;
    char *name_local = NULL;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(name, &rc, cleanup, "input argument name is null");

    name_local = calloc(strlen(name)+1, sizeof(char));
    CHECK_NULL_MSG(name_local, &rc, cleanup, "memory allocation for name failed");

    strncpy(name_local, name, strlen(name));

    if (ubus_object->name != NULL) free(ubus_object->name);
    ubus_object->name = name_local;

    return rc;

cleanup:
    free(name_local);
    return rc;
}

int ubus_object_set_yang_module(ubus_object_t *ubus_object, const char *yang_module)
{
    int rc = SR_ERR_OK;
    char *yang_module_local = NULL;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(yang_module, &rc, cleanup, "input argument yang_module is null");

    yang_module_local = calloc(strlen(yang_module)+1, sizeof(char));
    CHECK_NULL_MSG(yang_module_local, &rc, cleanup, "memory allocation for yang_module failed");

    strncpy(yang_module_local, yang_module, strlen(yang_module));

    if (ubus_object->yang_module != NULL) free(ubus_object->yang_module);
    ubus_object->yang_module = yang_module_local;

    return rc;

cleanup:
    free(yang_module_local);
    return rc;
}


int ubus_object_subscribe(sr_session_ctx_t *session, void *private_ctx, ubus_object_t *ubus_object, int (*f)(const char *, sr_val_t **, size_t *, uint64_t, const char *, void *))
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(private_ctx, &rc, cleanup, "input argument private_ctx is null");
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(session, &rc, cleanup, "input argument session is null");
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(f, &rc, cleanup, "input argument f is null");

    char xpath[256 + 1] = {0};
    snprintf(xpath, strlen(ubus_object->yang_module) + 4, "/%s:*", ubus_object->yang_module);

    INF_MSG("Subscribing to operational");
	rc = sr_dp_get_items_subscribe(session,
								   xpath,
								   f, // replace with type definition for state data callback
								   private_ctx,
								   SR_SUBSCR_CTX_REUSE,
								   &ubus_object->state_data_subscription);
    CHECK_RET(rc, cleanup, "dp subscription: %s", sr_strerror(rc));
cleanup:
    return rc;
}

int ubus_object_add_method(ubus_object_t *ubus_object, ubus_method_t *ubus_method)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");

    list_add(&ubus_method->list, &ubus_object->ubus_method_list);

cleanup:
    return rc;
}

int ubus_object_delete_method(ubus_object_t *ubus_object, const char *method_name)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(method_name, &rc, cleanup, "input argument method_name is null");

    ubus_method_t *ubus_method = NULL;
    rc = ubus_object_get_method(ubus_object, &ubus_method, method_name);
    CHECK_RET(rc, cleanup, "ubus method %s not found", method_name);

    list_del(&ubus_method->list);
    ubus_method_destroy(&ubus_method);

cleanup:
    return rc;
}

int ubus_object_delete_all_methods(ubus_object_t *ubus_object)
{
    int rc = SR_ERR_OK;
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

int ubus_object_get_name(ubus_object_t *ubus_object, char **name)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_object->name, &rc, cleanup, "ubus_object name is null");

    *name = ubus_object->name;

cleanup:
    return rc;
}

int ubus_object_get_yang_module(ubus_object_t *ubus_object, char **yang_module)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_object->yang_module, &rc, cleanup, "ubus_object yang_module is null");


    *yang_module = ubus_object->yang_module;

cleanup:
    return rc;
}

int ubus_object_get_method(ubus_object_t *ubus_object, ubus_method_t **ubus_method, const char *method_name)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");

    ubus_method_t *ubus_method_local = NULL;
    list_for_each_entry(ubus_method_local, &ubus_object->ubus_method_list, list)
    {
        if (strncmp(ubus_method_local->name, method_name, strlen(ubus_method_local->name)) == 0)
        {
            *ubus_method = ubus_method_local;
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
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    //CHECK_NULL_MSG(ubus_object->state_data_subscription, &rc, cleanup, "state_data_subscription is null");
    CHECK_NULL_MSG(session, &rc, cleanup, "input argument session is null");

    if (ubus_object->state_data_subscription != NULL)
    {
        INF_MSG("Unsubscribing from operational");
        rc = sr_unsubscribe(session, ubus_object->state_data_subscription);
        SR_CHECK_RET(rc, cleanup, "sr_unsubscribe: %s", sr_strerror(rc));

        ubus_object->state_data_subscription = NULL;
    }

cleanup:
    return rc;
}

int ubus_object_init_libyang_data(ubus_object_t *ubus_object, sr_session_ctx_t *session)
{
    int rc = SR_ERR_OK;
    struct ly_ctx *libyang_ctx = NULL;
    struct lys_module *libyang_module = NULL;
    char *sysrepo_schema = NULL;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input ubus_object is null");
    CHECK_NULL_MSG(session, &rc, cleanup, "input session is null");

    if (ubus_object->libyang_ctx != NULL) { ly_ctx_destroy(ubus_object->libyang_ctx, NULL); }
    // TODO : ly_ctx and module here
    ubus_object->libyang_ctx = NULL;
    libyang_ctx = ly_ctx_new(NULL, LY_CTX_ALLIMPLEMENTED );
    CHECK_NULL_MSG(libyang_ctx, &rc, cleanup, "libyang_ctx is null");


    rc = sr_get_schema(session, ubus_object->yang_module, NULL, NULL, SR_SCHEMA_YANG, &sysrepo_schema);
    CHECK_RET_MSG(rc, cleanup, "get schema from sysrepo error");

    libyang_module = (struct lys_module *) lys_parse_mem(libyang_ctx, sysrepo_schema, LYS_IN_YANG);
    CHECK_NULL_MSG(libyang_module, &rc, cleanup, "ly module  is null");

    ubus_object->libyang_ctx = libyang_ctx;
    ubus_object->libyang_module = libyang_module;

cleanup:

    free(sysrepo_schema);

    return rc;
}

int ubus_object_get_libyang_schema(ubus_object_t *ubus_object ,struct lys_module **module)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_object->libyang_ctx, &rc, cleanup, "ubus_object libyang_ctx is null");


    *module = ubus_object->libyang_module;

cleanup:
    return rc;
}

int ubus_object_clean_libyang_data(ubus_object_t *ubus_object)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input ubus_object is null");

    ly_ctx_destroy(ubus_object->libyang_ctx, NULL);

cleanup:
    return rc;
}

void ubus_object_destroy(ubus_object_t **ubus_object)
{
    if (*ubus_object != NULL)
    {
        free((*ubus_object)->name);
        free((*ubus_object)->yang_module);


        int rc = ubus_object_clean_libyang_data(*ubus_object);
        CHECK_RET_MSG(rc, cleanup, "clean ubus object libyang ");
        rc = ubus_object_delete_all_methods(*ubus_object);
        CHECK_RET_MSG(rc , cleanup, "ubus object delete all methods error");
    }
cleanup:
    free(*ubus_object);
    *ubus_object = NULL;
}