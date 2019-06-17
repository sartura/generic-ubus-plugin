
#include "ubus_call.h"
#include "common.h"

void ubus_get_response_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{

    if (msg == NULL) {
		return;
	}

    int rc = SR_ERR_OK;
    char **data = req->priv;

    char *result_str = blobmsg_format_json(msg, true);
    CHECK_NULL_MSG(result_str, &rc, cleanup, "json data is null");

    *data = strdup(result_str);

cleanup:
    free(result_str);
    return;
}

// TODO: replace current calls with this and test
int ubus_call(const char *ubus_object_name, const char *ubus_method_name, const char *ubus_message, void(*f)(struct ubus_request *, int, struct blob_attr *), char **result)
{
    int rc = SR_ERR_OK;
    struct blob_buf buf = {0};
    int urc = UBUS_STATUS_OK;
    struct ubus_context *ubus_ctx = NULL;
    unsigned int ubus_id = 0;

    CHECK_NULL_MSG(ubus_object_name, &rc, cleanup, "input argument ubus_object_name is null");
    CHECK_NULL_MSG(ubus_method_name, &rc, cleanup, "input argument ubus_method_name is null");
    CHECK_NULL_MSG(f, &rc, cleanup, "input argument f is null");

    ubus_ctx = ubus_connect(NULL);
    CHECK_NULL_MSG(ubus_ctx, &rc, cleanup, "ubus context is null");

    urc = ubus_lookup_id(ubus_ctx, ubus_object_name, &ubus_id);
    UBUS_CHECK_RET_MSG(urc, &rc, cleanup, "ubus lookup id error");

    blob_buf_init(&buf, 0);
    if (ubus_message != NULL)
    {
        blobmsg_add_json_from_string(&buf, ubus_message);
    }

    *result = NULL;
    urc = ubus_invoke(ubus_ctx, ubus_id, ubus_method_name, buf.head, f, result, 1000);
    UBUS_CHECK_RET(urc, &rc, cleanup, "ubus invoke error: %d", urc);

cleanup:
    if (ubus_ctx != NULL) {
		ubus_free(ubus_ctx);
	}

    blob_buf_free(&buf);

    return rc;
}