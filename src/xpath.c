#include <string.h>

#include "xpath.h"
#include "common.h"

// TODO: fix error handling

int xpath_get_list_node(const char *xpath, char **node)
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
    CHECK_NULL_MSG(nth_ptr, &rc, cleanup, "'/' is not found in string");

    int len = strlen(nth_ptr);

    char *name = calloc(1, sizeof(char)*len + 1);
    CHECK_NULL_MSG(name, &rc, cleanup, "allocation for name error");
    strncpy(name, nth_ptr, len);
    name[len] = '\0';

    *node = name;
cleanup:
    return rc;
}

int xpath_get_last_list_attribute_name(const char *xpath, char **attribute_name)
{
    int rc = SR_ERR_OK;
    *attribute_name = NULL;
    CHECK_NULL_MSG(xpath, &rc, cleanup, "input argument xpath is null");

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

    char *name = calloc(1, sizeof(char)*len + 1);
    CHECK_NULL_MSG(name, &rc, cleanup, "allocation for name error");
    strncpy(name, nth_ptr+1, len);
    name[len] = '\0';

    *attribute_name = name;
cleanup:
    return rc;
}