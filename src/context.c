#include "context.h"

int context_create(context_t **context)
{
    int rc = 0;
    *context = calloc(1, sizeof(context_t));
    CHECK_NULL_MSG(*context, &rc, cleanup, "input argument context is null");

    (*context)->session = NULL;
    (*context)->startup_connection = NULL;
    (*context)->startup_session = NULL;
    (*context)->subscription = NULL;
    INIT_LIST_HEAD(&(*context)->ubus_object_list);

cleanup:
    return rc;
}

int context_set_session(context_t *context, sr_session_ctx_t *session)
{
    int rc = 0;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(session, &rc, cleanup, "input argument session is null");

    context->session = session;

cleanup:
    return rc;
}

int context_set_subscription(context_t *context, sr_subscription_ctx_t *subscription)
{
    int rc = 0;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(subscription, &rc, cleanup, "input argument subscription is null");

    context->subscription = subscription;

cleanup:
    return rc;
}

int context_set_startup_session(context_t *context, sr_session_ctx_t *session)
{
    int rc = 0;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(session, &rc, cleanup, "input argument session is null");

    context->startup_session = session;

cleanup:
  return rc;
}

int context_set_startup_connection(context_t *context, sr_conn_ctx_t *connection)
{
    int rc = 0;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(connection, &rc, cleanup, "input argument connection is null");

    context->startup_connection = connection;

cleanup:
    return rc;
}

int context_get_session(context_t *context, sr_session_ctx_t **session)
{
    int rc = 0;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(context->session, &rc, cleanup, "context session is null");

    *session = context->session;

cleanup:
    return rc;
}

int context_get_subscription(context_t *context, sr_subscription_ctx_t **subscription)
{
    int rc = 0;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(context->subscription, &rc, cleanup, "context subscription is null");

    *subscription = context->subscription;

cleanup:
    return rc;
}
int context_get_startup_session(context_t *context, sr_session_ctx_t **session)
{
    int rc = 0;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(context->startup_session, &rc, cleanup, "context startup_session is null");

    *session = context->startup_session;

cleanup:
  return rc;
}
int context_get_startup_connection(context_t *context, sr_conn_ctx_t **connection)
{
    int rc = 0;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(context->startup_connection, &rc, cleanup, "context connection is null");

    *connection = context->startup_connection;

cleanup:
    return rc;
}

int context_get_ubus_object(context_t *context, ubus_object_t **ubus_object, const char *ubus_object_name)
{
    int rc = 0;
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

int context_add_ubus_object(context_t *context, ubus_object_t *ubus_object)
{
    int rc = 0;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");

    list_add(&ubus_object->list, &context->ubus_object_list);

cleanup:
    return rc;
}

int context_delete_ubus_object(context_t *context, const char *ubus_object_name)
{
    int rc = 0;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(ubus_object_name, &rc, cleanup, "input argument ubus_object_name is null");

    ubus_object_t *ubus_object = NULL;
    rc = context_get_ubus_object(context, &ubus_object, ubus_object_name);
    CHECK_RET(rc, cleanup, "ubus method %s not found", ubus_object_name);

    list_del(&ubus_object->list);
    // TODO: unsubscribe
    ubus_object_destroy(&ubus_object);

cleanup:
    return rc;
}

int context_delete_all_ubus_object(context_t *context)
{
     int rc = 0;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    ubus_object_t *ubus_object_p = NULL;
    ubus_object_t *ubus_object_n = NULL;
    list_for_each_entry_safe(ubus_object_p, ubus_object_n, &context->ubus_object_list, list)
    {
        list_del(&ubus_object_p->list);
        ubus_object_destroy(&ubus_object_p);
    }

cleanup:
    return rc;
}

void context_destroy(context_t **context)
{
    if (*context != NULL)
    {
        int rc = 0;
        if ((*context)->startup_session != NULL)
        {
            rc = sr_session_stop((*context)->startup_session);
            if (rc != SR_ERR_OK) ERR("%s: %s", __func__, sr_strerror(rc)); // TODO: handle
        }
        if ((*context)->startup_connection != NULL)
        {
            sr_disconnect((*context)->startup_connection);
        }

        ubus_object_t *ubus_object = NULL;
        list_for_each_entry(ubus_object, &(*context)->ubus_object_list, list)
        {
            rc = ubus_object_unsubscribe((*context)->session, ubus_object);
            if (rc != SR_ERR_OK) ERR("%s: %s", __func__, sr_strerror(rc)); // TODO: handle
        }

        rc = context_delete_all_ubus_object(*context);
        if (rc != SR_ERR_OK) ERR("%s: %s", __func__, sr_strerror(rc)); // TODO: handle

        if ((*context)->subscription != NULL)
        {
            rc = sr_unsubscribe((*context)->session, (*context)->subscription);
            if (rc != SR_ERR_OK) ERR("%s: %s", __func__, sr_strerror(rc)); // TODO: handle
        }
#if PLUGIN
        if ((*context)->session != NULL)
        {
            rc = sr_session_stop((*context)->session);
            if (rc != SR_ERR_OK) ERR("%s: %s", __func__, sr_strerror(rc)); // TODO: handle
        }
#endif
    }
    free(*context);
    *context = NULL;
}
