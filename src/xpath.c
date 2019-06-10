#include <string.h>

#include "sysrepo/xpath.h"

#include "xpath.h"
#include "common.h"


int xpath_get_tail_list_node(const char *xpath, char **node)
{
    int rc = SR_ERR_OK;
    *node = NULL;
    CHECK_NULL_MSG(xpath, &rc, cleanup, "input argument xpath is null");
    char* nth_ptr;

    char partial_xpath[256+1] = {0};

    int start_index = 0, end_index = 0;

    nth_ptr=strrchr(xpath, '[');
    if (nth_ptr == NULL)
    {
        rc = -2;
        goto cleanup;
    }
    end_index = (int)(nth_ptr - xpath + 1);

    snprintf(partial_xpath, end_index, "%s", xpath);

    nth_ptr=strrchr(partial_xpath, '/');
    if (nth_ptr == NULL)
    {
        rc = -2;
        goto cleanup;
    }
    start_index = (int)(nth_ptr - partial_xpath + 1);

    int len = end_index - start_index;

    char *name = calloc(1, sizeof(char)*len + 1);
    CHECK_NULL_MSG(name, &rc, cleanup, "allocation for name error");
    strncpy(name, nth_ptr+1, len);
    name[len] = '\0';

    *node = name;

cleanup:
    return rc;
}

int xpath_get_tail_node(const char *xpath, char **node)
{
    int rc = SR_ERR_OK;
    *node = NULL;
    CHECK_NULL_MSG(xpath, &rc, cleanup, "input argument xpath is null");
    char* nth_ptr;

    nth_ptr=strrchr(xpath, '/');
    if (nth_ptr == NULL)
    {
        INF_MSG("'/' is not found");
        return -2;
    }
    //CHECK_NULL_MSG(nth_ptr, &rc, cleanup, "'/' is not found in string");

    int len = strlen(nth_ptr);

    char *name = calloc(1, sizeof(char)*len + 1);
    CHECK_NULL_MSG(name, &rc, cleanup, "allocation for name error");
    strncpy(name, nth_ptr+1, len);
    name[len] = '\0';

    *node = name;
cleanup:
    return rc;
}

int xpath_get_node_key_value(char *xpath, const char *node_name, const char *key_name, char **key_value)
{
    int rc = SR_ERR_OK;
    *key_value = NULL;
    CHECK_NULL_MSG(xpath, &rc, cleanup, "input argument xpath is null");
    CHECK_NULL_MSG(node_name, &rc, cleanup, "input argument node_name is null");
    CHECK_NULL_MSG(key_name, &rc, cleanup, "input argument key_name is null");
/*
    int start_index = 0, end_index = 0;
    char* nth_ptr;
    char partial_xpath[256+1] = {0};

    nth_ptr=strrchr(xpath, '\'');
    CHECK_NULL_MSG(nth_ptr, &rc, cleanup, "' is not found in string");
    end_index = (int)(nth_ptr - xpath + 1);

    snprintf(partial_xpath, end_index, "%s", xpath);

    nth_ptr=strrchr(partial_xpath, '\'');
    CHECK_NULL_MSG(nth_ptr, &rc, cleanup, "' is not found in string");
    start_index = (int)(nth_ptr - partial_xpath + 1);

    int len = end_index - start_index;
*/
    sr_xpath_ctx_t ctx;
    char *key_val = sr_xpath_key_value(xpath, node_name, key_name, &ctx);
    CHECK_NULL_MSG(key_val, &rc, cleanup, "key value not found");
    int len = strlen(key_val);
    char *value = calloc(1, sizeof(char)*len + 1);
    CHECK_NULL_MSG(value, &rc, cleanup, "allocation for name error");
    strncpy(value, key_val, len);
    value[len] = '\0';

    *key_value = value;
cleanup:
    sr_xpath_recover(&ctx);
    return rc;
}

int xpath_get_module_name(const char *xpath, char **module_name)
{
    int rc = SR_ERR_OK;
    *module_name = NULL;
    CHECK_NULL_MSG(xpath, &rc, cleanup, "input argument xpath is null");

    char *nth_ptr = strchr(xpath, ':');
    CHECK_NULL_MSG(nth_ptr, &rc, cleanup, "':' not found");

    int len = (int)(nth_ptr - xpath - 1);

    char *module = calloc(1, sizeof(char)*len + 1);
    CHECK_NULL_MSG(module, &rc, cleanup, "allocation for module error");
    strncpy(module, xpath+1, len);
    module[len] = '\0';

    *module_name = module;

    INF("%s", *module_name);

cleanup:
    return rc;
}
