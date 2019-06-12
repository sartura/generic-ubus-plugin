#ifndef _UBUS_CALL_H_
#define _UBUS_CALL_H_

#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

void ubus_get_response_cb(struct ubus_request *req, int type, struct blob_attr *msg);
int ubus_call(const char *ubus_object_name, const char *ubus_method_name, const char *ubus_message, void(*f)(struct ubus_request *, int, struct blob_attr *), char **result);

#endif //__UBUS_CALL_