#include "ubus_method.h"
#include "common.h"

int ubus_method_create(ubus_method_t **ubus_method, const char *name, const char *message)
{
    int rc = 0;
    char *name_local = NULL;
    char *message_local = NULL;

    CHECK_NULL_MSG(name, &rc, cleanup, "input argument name is null");
    CHECK_NULL_MSG(message, &rc, cleanup, "input argument message is null");

    *ubus_method = calloc(1, sizeof(ubus_method_t));
    CHECK_NULL_MSG(*ubus_method, &rc, cleanup, "return argument ubus_method is null");

    name_local = calloc(strlen(name), sizeof(char));
    CHECK_NULL_MSG(name_local, &rc, cleanup, "memory allocation for name failed");
    message_local = calloc(strlen(message), sizeof(char));
    CHECK_NULL_MSG(message_local, &rc, cleanup, "memory allocation for yang_module failed");

    strncpy(name_local, name, strlen(name_local));
    strncpy(message_local, message, strlen(message_local));

    (*ubus_method)->name = name_local;
    (*ubus_method)->message = message_local;

    return rc;

cleanup:
    free(name_local);
    free(message_local);
    free(ubus_method);
    return rc;
}


int ubus_method_get_name(ubus_method_t *ubus_method, char **name)
{
    int rc = 0;
    CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");
    CHECK_NULL_MSG(ubus_method->name, &rc, cleanup, "ubus_metehod name is null");

    *name = ubus_method->name;

cleanup:
    return rc;
}

int ubus_method_get_message(ubus_method_t *ubus_method, char **message)
{
    int rc = 0;
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