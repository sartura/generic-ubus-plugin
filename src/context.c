//#include <sys/inotify.h>
#include <stdlib.h>
#include <regex.h>

#include "context.h"

int context_create(context_t **context)
{
    int rc = SR_ERR_OK;
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
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(session, &rc, cleanup, "input argument session is null");

    context->session = session;

cleanup:
    return rc;
}

int context_set_subscription(context_t *context, sr_subscription_ctx_t *subscription)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(subscription, &rc, cleanup, "input argument subscription is null");

    context->subscription = subscription;

cleanup:
    return rc;
}

int context_set_startup_session(context_t *context, sr_session_ctx_t *session)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(session, &rc, cleanup, "input argument session is null");

    context->startup_session = session;

cleanup:
  return rc;
}

int context_set_startup_connection(context_t *context, sr_conn_ctx_t *connection)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(connection, &rc, cleanup, "input argument connection is null");

    context->startup_connection = connection;

cleanup:
    return rc;
}

int context_get_session(context_t *context, sr_session_ctx_t **session)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(context->session, &rc, cleanup, "context session is null");

    *session = context->session;

cleanup:
    return rc;
}

int context_get_subscription(context_t *context, sr_subscription_ctx_t **subscription)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(context->subscription, &rc, cleanup, "context subscription is null");

    *subscription = context->subscription;

cleanup:
    return rc;
}
int context_get_startup_session(context_t *context, sr_session_ctx_t **session)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(context->startup_session, &rc, cleanup, "context startup_session is null");

    *session = context->startup_session;

cleanup:
  return rc;
}
int context_get_startup_connection(context_t *context, sr_conn_ctx_t **connection)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(context->startup_connection, &rc, cleanup, "context connection is null");

    *connection = context->startup_connection;

cleanup:
    return rc;
}

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

int context_add_ubus_object(context_t *context, ubus_object_t *ubus_object)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");

    list_add(&ubus_object->list, &context->ubus_object_list);

cleanup:
    return rc;
}

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

int context_delete_all_ubus_object(context_t *context)
{
    int rc = SR_ERR_OK;
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

// TODO: free inotify file descriptor
void context_destroy(context_t **context)
{
    if (*context != NULL)
    {
        int rc = SR_ERR_OK;
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
/*
#if PLUGIN
        if ((*context)->session != NULL)
        {
            rc = sr_session_stop((*context)->session);
            if (rc != SR_ERR_OK) ERR("%s: %s", __func__, sr_strerror(rc)); // TODO: handle
        }
#endif
*/
    }
    free(*context);
    *context = NULL;
}
/*
// TODO: maybe redundant
int context_init_ubus_object_filter(context_t *context)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");

    int fd = -1;
    int wd = -1;

    fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1)
    {
        rc = SR_ERR_INTERNAL;
        ERR_MSG("error initializing inotify file descriptor");
    }

    wd = inotify_add_watch(fd, WATCH_FILE, IN_DELETE_SELF | IN_CLOSE_WRITE);
    if ( wd == -1)
    {
        rc = SR_ERR_INTERNAL;
        ERR("can't watch file %s", WATCH_FILE);
    }

    context->inotify_fd = fd;
    context->inotify_wd = wd;

    return rc;

cleanup:
    if (fd != -1) { close(fd); }
    return rc;
}
*/
int context_filter_ubus_object(context_t *context, const char *ubus_object_name, bool *skip)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(context, &rc, cleanup, "input argument context is null");
    CHECK_NULL_MSG(ubus_object_name, &rc, cleanup, "input argument ubus_object_name is null");
    *skip = false;

    char file_ubus_object_name[256+1];
    regex_t regular_expression;
    int regrc = 0;

    // TODO: maybe inotify is redundant?
    FILE *fd = fopen(UBUS_OBJECT_FILTER_WATCH_FILE, "r");
    if (fd == NULL)
    {
        rc = SR_ERR_INTERNAL;
        ERR_MSG("error initializing inotify file descriptor");
        return rc;
    }

    while(true)
    {
        memset(file_ubus_object_name, 0, 256+1);
        int scanned_line = fscanf(fd, "%s\n", file_ubus_object_name);
        if (scanned_line == EOF) { break; }

        // TODO: replace with regex matching
        regrc = regcomp(&regular_expression, file_ubus_object_name, 0);
        if (regrc != 0)
        {
            rc = SR_ERR_INTERNAL;
        }

        regrc = regexec(&regular_expression, ubus_object_name, 0, NULL, 0);
        if (regrc == 0) {
            INF_MSG("regex match");
            *skip = true;
            regfree(&regular_expression);
            break;
        }
        else if (regrc == REG_NOMATCH)
        {
            *skip = false;
            INF_MSG("regex no match");
        }
        else
        {
            rc = SR_ERR_INTERNAL;
            ERR("regexec error: %d", regrc);
        }
        regfree(&regular_expression);
    }


cleanup:
    if (fd != NULL) { fclose(fd); }
    return rc;
}
