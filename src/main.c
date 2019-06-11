#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "sysrepo.h"
#include "sysrepo/values.h"

#include "context.h"
#include "generic_ubus.h"
#include "common.h"
#include "xpath.h"


static int generic_ubus_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	context_t *context = (context_t *)private_ctx;

	INF("%d", event);

	if (SR_EV_APPLY == event)
	{
		/* copy running datastore to startup */
        rc = sr_copy_config(context->startup_session, YANG_MODEL, SR_DS_RUNNING, SR_DS_STARTUP);
        if (SR_ERR_OK != rc) {
            WRN_MSG("Failed to copy running datastore to startup");
            /* TODO handle this error */
            return rc;
		}
		return SR_ERR_OK;
	}

	INF_MSG("TODO: apply the changes from yang module");
	rc = generic_ubus_apply_module_changes(context, module_name, session);
	return rc;
}

// TODO: add multiple ubus object support
static int generic_ubus_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char *tail_node = NULL;
	char *ubus_object_name = NULL;
	char *ubus_method_name = NULL;
	char *ubus_message = NULL;
	int urc = UBUS_STATUS_OK;
	struct ubus_context *ubus_ctx = NULL;
    unsigned int ubus_id = 0;
	struct blob_buf buf = {0};
	sr_val_t *result = NULL;
	*output_cnt = 0;

	// get the expected data an create a ubus call
	for (int i = 0; i < input_cnt; i++)
	{
		rc = xpath_get_tail_node(input[i].xpath, &tail_node);
		CHECK_RET_MSG(rc, cleanup, "get tail node error");

		if (strcmp("ubus-object", tail_node) == 0) { ubus_object_name = input[i].data.string_val; }
		else if (strcmp("ubus-method", tail_node) == 0) { ubus_method_name = input[i].data.string_val; }
		else if (strcmp("ubus-method-message", tail_node) == 0) { ubus_message = input[i].data.string_val; }

		free(tail_node);
		tail_node = NULL;
	}

	// buffer, ubus call
	ubus_ctx = ubus_connect(NULL);
	CHECK_NULL_MSG(ubus_ctx, &rc, cleanup, "ubus context is null");

	urc = ubus_lookup_id(ubus_ctx, ubus_object_name, &ubus_id);
	UBUS_CHECK_RET_MSG(urc, &rc, cleanup, "ubus lookup id error");

	blob_buf_init(&buf, 0);
	if (ubus_message != NULL)
	{
		blobmsg_add_json_from_string(&buf, ubus_message);
	}

	char *result_json_data = NULL;
	urc = ubus_invoke(ubus_ctx, ubus_id, ubus_method_name, buf.head, ubus_get_response_cb, &result_json_data, 1000);
	UBUS_CHECK_RET_MSG(urc, &rc, cleanup, "ubus invoke error");

	blob_buf_free(&buf);

	rc = sr_new_values(1, &result);
	SR_CHECK_RET(rc, cleanup, "sr new values error: %s", sr_strerror(rc));

	rc = sr_val_set_xpath(result, "/terastream-generic-ubus:ubus-call/ubus-response");
	SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

	rc = sr_val_set_str_data(result, SR_STRING_T, result_json_data);
	SR_CHECK_RET(rc, cleanup, "sr value set str data: %s", sr_strerror(rc));

	*output_cnt = 1;
	*output = result;

cleanup:
	if (ubus_ctx != NULL) {
		ubus_free(ubus_ctx);
	}

	free(tail_node);
	free(result_json_data);
	blob_buf_free(&buf);
	return rc;
}

/*
static int
#if defined(SYSREPO_LESS_0_7_5)
generic_ubus_operational_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
#elif defined(SYSREPO_LESS_0_7_7)
generic_ubus_operational_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, void *private_ctx)
#else
generic_ubus_operational_cb(const char *cb_xpath,
							sr_val_t **values,
							size_t *values_cnt,
							uint64_t request_id,
							const char *original_xpath,
							void *private_ctx)
#endif
{
	// TODO: add logic
	INF("%s", __func__);
	*values_cnt = 0;
	return SR_ERR_OK;
}
*/
int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
	// TODO: add logic
	INF("%s", __func__);

	int rc = SR_ERR_OK;
	context_t *context = NULL;
	rc = context_create(&context);
	SR_CHECK_RET(rc, cleanup, "%s: context_create: %s", __func__, sr_strerror);

	rc = context_set_session(context, session);
	SR_CHECK_RET(rc, cleanup, "%s: context_create: %s", __func__, sr_strerror);

	*private_ctx = context;

	sr_conn_ctx_t *startup_connection = NULL;
	rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &startup_connection);
    CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

	sr_session_ctx_t *startup_session = NULL;
    rc = sr_session_start(startup_connection, SR_DS_STARTUP, SR_SESS_CONFIG_ONLY, &startup_session);
	CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

	rc = context_set_startup_connection(context, startup_connection);
	SR_CHECK_RET(rc, cleanup, "context error: %s", sr_strerror(rc));

	rc = context_set_startup_session(context, startup_session);
	SR_CHECK_RET(rc, cleanup, "context error: %s", sr_strerror(rc));

	// load startup datastore
	rc = generic_ubus_load_startup_datastore(context);
	SR_CHECK_RET(rc, cleanup, "context error: %s", sr_strerror(rc));

	INF_MSG("Subcribing to module change");
	rc = sr_module_change_subscribe(session, YANG_MODEL, generic_ubus_change_cb, *private_ctx, 0, SR_SUBSCR_DEFAULT, &context->subscription);
	SR_CHECK_RET(rc, cleanup, "initialization error: %s", sr_strerror(rc));

	INF_MSG("Subscribing to rpc");
	rc = sr_rpc_subscribe(session, "/terastream-generic-ubus:ubus-call", generic_ubus_rpc_cb, NULL, SR_SUBSCR_CTX_REUSE, &context->subscription);
	SR_CHECK_RET(rc, cleanup, "rpc subscription error: %s", sr_strerror(rc));
/*
	INF_MSG("Subscribing to operational");
	rc = sr_dp_get_items_subscribe(session,
								   "/terastream-wireless:devices-state",
								   generic_ubus_operational_cb,
								   *private_ctx,
								   SR_SUBSCR_CTX_REUSE,
								   &ctx->subscription);

	SR_CHECK_RET(rc, error, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));
*/

	INF_MSG("Succesfull init");
	return SR_ERR_OK;

cleanup:
	context_destroy(&context);
	return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
	INF("%s", __func__);
	INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");

	if (NULL != private_ctx)
	{
		context_t *context = private_ctx;
		context_destroy(&context);
	}
	INF_MSG("Plugin cleaned-up successfully");
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum)
{
	INF_MSG("Sigint called, exiting...");
	exit_application = 1;
}

int main(void)
{
	INF_MSG("Plugin application mode initialized");
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_ctx = NULL;
	int rc = SR_ERR_OK;

	/* connect to sysrepo */
	INF_MSG("Connecting to sysrepo ...");
	rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &connection);
	SR_CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

	/* start session */
	INF_MSG("Starting session ...");
	rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
	SR_CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

	INF_MSG("Initializing plugin ...");
	rc = sr_plugin_init_cb(session, &private_ctx);
	SR_CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1); /* or do some more useful work... */
	}

	sr_plugin_cleanup_cb(session, private_ctx);

cleanup:
		if (NULL != session) {
			rc = sr_session_stop(session);
			if (rc != SR_ERR_OK) INF("cleanup: %s", sr_strerror(rc));
		}
		if (NULL != connection) {
			sr_disconnect(connection);
		}
	return rc;
}
#endif
