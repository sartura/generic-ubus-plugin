#include "parse.h"
#include "sysrepo.h"
#include "sysrepo/values.h"


int load_startup_datastore(struct global_context_s *ctx)
{
    // TODO:
    return 0;
}

// TODO: rewrite so partial xpath string is as argument
// get ubus object name is not needed
char *get_ubus_object_method_name(char *xpath)
{
    char *partial_xpath = strstr(xpath, "/method[name='");
    if (NULL == partial_xpath) return NULL;

    int start_index = 0, end_index = 0;
    char* nth_ptr;

    nth_ptr=strchr(partial_xpath, '\'');
    start_index = (int)(nth_ptr - partial_xpath + 1);
    //INF("%s %d", nth_ptr, start_index);
    nth_ptr=strchr(nth_ptr + 1, '\'');
    end_index = (int)(nth_ptr - partial_xpath);
    //INF("%s %d", nth_ptr, end_index);
    int len = end_index - start_index;

    char *name = calloc(1, sizeof(*name)*len + 1);
    if (NULL == name) return NULL;
    strncpy(name, partial_xpath+start_index, len);
    name[len] = '\0';

    return name;
}

struct ubus_message_s *get_ubus_object_method_from_list(struct list_head *head,
                                                const char *method_name)
{
    if (NULL == method_name) return NULL;
    // got through the list and return
    struct ubus_message_s *m = NULL;
    list_for_each_entry(m, head, method_list)
    {
        INF("%s", method_name);
        INF("%s", m->method_name);
        if (0 == strcmp(method_name, m->method_name))
        {
            return m;
        }
    }
    return NULL;
}

// set primitive data ie. names
int set_ubus_object(struct ubus_object_s *uobj, sr_val_t *sr_value)
{
    int rc = 0;
    char *method_name = NULL;
    char *xpath_leaf = sr_value->xpath +
                       (strrchr(sr_value->xpath, '/') - sr_value->xpath + 1);
    // ubus object name and method name are set upon creating the list
    // because they are used as keys in the lists so it is not necessary
    // to set them here

    if (0 == strncmp("yang-module", xpath_leaf, 11))
    {
        INF_MSG("yang-module");
        int len = strlen(sr_value->data.string_val) + 1;
        INF("%d", len);
        uobj->yang_module = calloc(1, sizeof(*uobj->yang_module)*len);
        if (NULL == uobj->yang_module)
        {
            WRN_MSG("no ubus method message allocated");
            rc = 2;
            goto clean;
        }
        snprintf(uobj->yang_module, len, "%s", sr_value->data.string_val);
        INF("YANG module: %s", uobj->yang_module);
        // TODO: change subbscription if necessary
        // TODO: subscribe to operational data
    }
    else if (0 == strncmp("message", xpath_leaf, 7))
    {
        INF_MSG("object_name");
        INF("XPATH %s", sr_value->xpath);
        INF("Message: %s", sr_value->data.string_val);
        method_name = get_ubus_object_method_name(sr_value->xpath);
        INF("Method name %s", method_name);
        struct ubus_message_s *method = get_ubus_object_method_from_list(
                                &uobj->ubus_object_method_list, method_name);

        int len = strlen(sr_value->data.string_val) + 1;
        INF("%d", len);
        method->method_message = calloc(1, sizeof(*method->method_message)*len);
        if (NULL == method->method_message)
        {
            WRN_MSG("no ubus method message allocated");
            rc = 2;
            goto clean;
        }
        snprintf(method->method_message, len, "%s", sr_value->data.string_val);
        INF("Method obj: %s %s", method->method_name, method->method_message);

    }
clean:
    free(method_name);
    return rc;
}

char *get_ubus_object_name(const char *xpath)
{
    char *partial_xpath = strstr(xpath, "/ubus-object[name='");
    if (NULL == partial_xpath) return NULL;

    int start_index = 0, end_index = 0;
    char* nth_ptr;

    nth_ptr=strchr(partial_xpath, '\'');
    start_index = (int)(nth_ptr - partial_xpath + 1);
    //INF("%s %d", nth_ptr, start_index);
    nth_ptr=strchr(nth_ptr + 1, '\'');
    end_index = (int)(nth_ptr - partial_xpath);
    //INF("%s %d", nth_ptr, end_index);
    int len = end_index - start_index;

    char *name = calloc(1, sizeof(*name)*len + 1);
    if (NULL == name) return NULL;
    strncpy(name, partial_xpath+start_index, len);
    name[len] = '\0';

    return name;
}
struct ubus_object_s *get_ubus_object_from_list(struct list_head *head,
                                                const char *uobject_name)
{
    if (NULL == uobject_name) return NULL;
    // got through the list and return
    struct ubus_object_s *obj = NULL;
    list_for_each_entry(obj, head, object_list)
    {
        INF("%s", uobject_name);
        INF("%s", obj->ubus_object);
        if (0 == strcmp(uobject_name, obj->ubus_object))
        {
            return obj;
        }
    }
    return NULL;
}

int create_ubus_object_procedure(struct global_context_s *ctx,
                                        sr_val_t *new_value)
{
    int rc = 0;

    INF_MSG("ubus-object list created");
    char *uobj_name = get_ubus_object_name(new_value->xpath);
    INF("%s", uobj_name);
    // create new ubus object
    struct ubus_object_s *uobject = NULL;
    uobject = calloc(1, sizeof(*uobject));
    if (NULL == uobject)
    {
        WRN_MSG("no ubus object allocated");
        rc = 1;
        goto clean;
    }
    INIT_LIST_HEAD(&uobject->ubus_object_method_list);
    // add object name
    int len = strlen(uobj_name) + 1;
    uobject->ubus_object = calloc(1,
            sizeof(*uobject->ubus_object)*len);
    if (NULL == uobject->ubus_object)
    {
        WRN_MSG("no ubus object name allocated");
        rc = 2;
        goto clean;
    }
    // add to list
    snprintf(uobject->ubus_object, len, "%s", uobj_name);
    list_add(&uobject->object_list, &ctx->ubus_object_list);
clean:
    free(uobj_name);
    return rc;
}

int create_ubus_object_method_procedure(struct global_context_s *ctx,
                                 sr_val_t *new_value)
{
    int rc = 0;

    INF_MSG("method list created");
    // find the object from list using the ubus-object name
    // from xpath
    char *uobj_name = get_ubus_object_name(new_value->xpath);
    INF("%s", uobj_name);

    struct ubus_object_s *uobject = get_ubus_object_from_list(
                            &ctx->ubus_object_list, uobj_name);
    // create new method
    if (NULL == uobject)
    {
        WRN_MSG("no ubus object fount in list");
        rc = 1;
        goto clean;
    }
    INF("ubus object name: %s", uobject->ubus_object);

    struct ubus_message_s *method = NULL;
    method = calloc(1, sizeof(*method));
    if (NULL == method)
    {
        rc = 2;
        goto clean;
    }
    // add method name
    char *method_name = get_ubus_object_method_name(new_value->xpath);
    int len = strlen(method_name) + 1;
    method->method_name = calloc(1,
            sizeof(*method->method_name)*len);
    if (NULL == method->method_name)
    {
        WRN_MSG("no method name allocated");
        rc = 3;
        goto clean;
    }
    // add to list
    snprintf(method->method_name, len, "%s", method_name);
    list_add(&method->method_list, &uobject->ubus_object_method_list);

clean:
    free(method_name);
    free(uobj_name);
    return rc;
}

int modify_ubus_object_procedure(struct global_context_s *ctx,
                                 sr_val_t *new_value)
{
    int rc = 0;
    char *uobj_name = get_ubus_object_name(new_value->xpath);
    INF("%s", uobj_name);

    struct ubus_object_s *uobject = get_ubus_object_from_list(
                                &ctx->ubus_object_list, uobj_name);

    if (NULL == uobject)
    {
        WRN_MSG("no ubus object from list");
        rc = 1;
        goto clean;
    }
    // and set the new data
    if ( 0 != (rc = set_ubus_object(uobject, new_value)))
    {
        WRN_MSG("no data set to ubus_object");
    }
clean:
    free(uobj_name);
    return rc;
}

int delete_ubus_object_procedure(struct global_context_s *ctx,
                                 sr_val_t *old_value)
{
    int rc = 0;

    char *uobject_name = get_ubus_object_name(old_value->xpath);
    struct list_head *head = &ctx->ubus_object_list;
    struct ubus_object_s *obj = NULL;
    list_for_each_entry(obj, head, object_list)
    {
        INF("%s", uobject_name);
        INF("%s", obj->ubus_object);
        if (0 == strcmp(uobject_name, obj->ubus_object))
        {
            free_ubus_object(obj, ctx->session);
        }
    }

    free(uobject_name);
    return rc;
}
//int delete_ubus_object_method_procedure

int parse_config(struct global_context_s *ctx, const char *module_name,
                 sr_session_ctx_t *session)
{
    // TODO: parse the configuration datastore and modify global_context_s
    INF("%s", __func__);
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_change_iter_t *it = NULL;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char xpath[256] = {0};

    snprintf(xpath, strlen(module_name) + 4, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, xpath, &it);
    if (SR_ERR_OK != rc) {
        printf("Get changes iter failed for xpath %s", xpath);
        goto error;
    }
    // TODO: package to a create method/object procedure, modify procedure
    while (SR_ERR_OK == sr_get_change_next(ctx->session, it, &oper,
                                           &old_value, &new_value)) {
        if (SR_OP_CREATED == oper && NULL != new_value && NULL == old_value)
        {
            // find out if a new list has been created
            // if so calloc and add to list
            if (SR_LIST_T == new_value->type)
            {
                INF_MSG("new data has been added to the model");
                if (NULL != strstr(new_value->xpath, "method"))
                {
                   if (0 != create_ubus_object_method_procedure(ctx, new_value))
                   {
                       goto clean;
                   }
                }
                else if (NULL != strstr(new_value->xpath, "ubus-object"))
                {
                    if (0 != create_ubus_object_procedure(ctx, new_value))
                    {
                        goto clean;
                    }
                }
            }
        }
        if ((SR_OP_MODIFIED == oper || SR_OP_CREATED == oper) &&
                    NULL != new_value)
        {
            if (new_value->type == SR_STRING_T)
            {
                INF_MSG("data has been modified in the model");
                // find the ubus object and set the new values
                sr_print_val(new_value);
                sr_print_val(old_value);
                // get the entry from the list of objects
                if (0 != modify_ubus_object_procedure(ctx, new_value))
                {
                    goto clean;
                }
            }
        }
        // TODO: finish delet logic
        if (SR_OP_DELETED == oper && NULL != old_value &&
                                            NULL == new_value)
        {
            sr_print_val(old_value);
            // unsubcribe for the module
            if (SR_LIST_T == old_value->type)
            {
                INF_MSG("list data has been deleted");
                if (NULL != strstr(old_value->xpath, "ubus-object"))
                {
                    INF_MSG("delete ubus object list");
                    // TODO: delete_ubus_object_procedure
                    if (0 != delete_ubus_object_procedure(ctx, old_value))
                    {
                        goto clean;
                    }
                }
                if (NULL != strstr(old_value->xpath, "method"))
                {
                    INF_MSG("delete method list");
                    // TODO: delete_ubus_object_method_procedure
                }
            }
            // free ubus object structure
            // free only method its the only thing deleted
        }
clean:
        sr_free_val(old_value);
        sr_free_val(new_value);
    }

error:
    if (NULL != it) {
        sr_free_change_iter(it);
    }
    return rc;
}
