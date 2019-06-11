#include "ubus_method.h"
#include "common.h"

int ubus_method_create(ubus_method_t **ubus_method)
{
    int rc = SR_ERR_OK;

    *ubus_method = calloc(1, sizeof(ubus_method_t));
    CHECK_NULL_MSG(*ubus_method, &rc, cleanup, "return argument ubus_method is null");

    (*ubus_method)->name = NULL;
    (*ubus_method)->message = NULL;

    return rc;

cleanup:
    free(ubus_method);
    return rc;
}

int ubus_method_set_name(ubus_method_t *ubus_method, const char *name)
{
    int rc = SR_ERR_OK;
    char *name_local = NULL;
    CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");
    CHECK_NULL_MSG(name, &rc, cleanup, "input argument name is null");

    name_local = calloc(strlen(name)+1, sizeof(char));
    CHECK_NULL_MSG(name_local, &rc, cleanup, "memory allocation for name failed");

    strncpy(name_local, name, strlen(name));

    if (ubus_method->name != NULL) free(ubus_method->name);
    ubus_method->name = name_local;

    return rc;

cleanup:
    free(name_local);
    return rc;
}

int ubus_method_set_message(ubus_method_t *ubus_method, const char *message)
{
    int rc = SR_ERR_OK;
    char *message_local = NULL;
    CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");
    CHECK_NULL_MSG(message, &rc, cleanup, "input argument message is null");

    message_local = calloc(strlen(message)+1, sizeof(char));
    CHECK_NULL_MSG(message_local, &rc, cleanup, "memory allocation for message failed");

    strncpy(message_local, message, strlen(message));

    if (ubus_method->message != NULL) free(ubus_method->message);
    ubus_method->message = message_local;

    return rc;

cleanup:
    free(message_local);
    return rc;
}

int ubus_method_get_name(ubus_method_t *ubus_method, char **name)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");
    CHECK_NULL_MSG(ubus_method->name, &rc, cleanup, "ubus_metehod name is null");

    *name = ubus_method->name;

cleanup:
    return rc;
}

int ubus_method_get_message(ubus_method_t *ubus_method, char **message)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");
    CHECK_NULL_MSG(ubus_method->message, &rc, cleanup, "ubus_metehod name is null");

    *message = ubus_method->message;

cleanup:
    return rc;
}

void ubus_method_destroy(ubus_method_t **ubus_method)
{
    if (*ubus_method != NULL)
    {
        free((*ubus_method)->name);
        free((*ubus_method)->message);
    }
    free(*ubus_method);
    *ubus_method = NULL;
}