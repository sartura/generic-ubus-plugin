#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "sysrepo.h"
#include "sysrepo/values.h"

#include "context.h"
#include "generic_ubus.h"
#include "common.h"
#include "xpath.h"
#include "ubus_call.h"

#define RPC_UBUS_OBJECT "ubus-object"
#define RPC_UBUS_METHOD "ubus-method"
#define RPC_UBUS_METHOD_MESSAGE "ubus-method-message"
#define RPC_UBUS_INVOCATION "ubus-invocation"
#define RPC_UBUS_INVOCATION_XPATH "/terastream-generic-ubus:ubus-call/ubus-result[ubus-invocation='%s']/ubus-invocation"
#define RPC_UBUS_RESPONSE_XPATH "/terastream-generic-ubus:ubus-call/ubus-result[ubus-invocation='%s']/ubus-response"
#define RPC_MODULE_PATH_XPATH "/terastream-generic-ubus:module-install/module-install-result[module-name-full='%s']/module-name-full"
#define RPC_MODULE_RESPONSE_XPATH "/terastream-generic-ubus:module-install/module-install-result[module-name-full='%s']/module-install-status"
#define RPC_FEATURE_INVOCATION_XPATH "/terastream-generic-ubus:feature-update/feature-update-result[feature-invocation-full='%s']/feature-invocation-full"
#define RPC_FEATURE_RESPONSE_XPATH  "/terastream-generic-ubus:feature-update/feature-update-result[feature-invocation-full='%s']/feature-update-status"
#define JSON_EMPTY_OBJECT "{}"


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
            return rc;
		}
		return SR_ERR_OK;
	}

	INF_MSG("TODO: apply the changes from yang module");
	rc = generic_ubus_apply_module_changes(context, module_name, session);
	return rc;
}

static int generic_ubus_ubus_call_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char *tail_node = NULL;
	char *ubus_object_name = NULL;
	char *ubus_method_name = NULL;
	char *ubus_message = NULL;
	sr_val_t *result = NULL;
	size_t count = 0;
	char ubus_invoke_string[256+1] = {0};
	char *result_json_data = NULL;

	*output_cnt = 0;

	INF("%d",input_cnt);

	for (int i = 0; i < input_cnt; i++)
	{
		rc = xpath_get_tail_node(input[i].xpath, &tail_node);
		CHECK_RET_MSG(rc, cleanup, "get tail node error");

		if (strcmp(RPC_UBUS_OBJECT, tail_node) == 0)
		{
			ubus_object_name = input[i].data.string_val;
		}
		else if (strcmp(RPC_UBUS_METHOD, tail_node) == 0)
		{
			ubus_method_name = input[i].data.string_val;
		}
		else if (strcmp(RPC_UBUS_METHOD_MESSAGE, tail_node) == 0)
		{
			ubus_message = input[i].data.string_val;
		}

		uint8_t last = (i + 1) >= input_cnt;

		if ((strstr(tail_node, RPC_UBUS_INVOCATION) != NULL && ubus_method_name != NULL && ubus_object_name != NULL ) || last == 1)
		{

			rc = ubus_call(ubus_object_name, ubus_method_name, ubus_message, ubus_get_response_cb, &result_json_data);
			CHECK_RET_MSG(rc, cleanup, "ubus call error");

			rc = sr_realloc_values(count, count + 2, &result);
			SR_CHECK_RET(rc, cleanup, "sr realloc values error: %s", sr_strerror(rc));

			memset(ubus_invoke_string, 0, 256+1);
			int len = strlen(ubus_object_name) + strlen(ubus_method_name) + 2;
			if (ubus_message != NULL)
			{
				len += (strlen(ubus_message) + 1);
				snprintf(ubus_invoke_string, len, "%s %s %s", ubus_object_name, ubus_method_name, ubus_message);
			}
			else
			{
				len += (4 + 1);
				snprintf(ubus_invoke_string, len, "%s %s %s", ubus_object_name, ubus_method_name, JSON_EMPTY_OBJECT);
			}

			rc = sr_val_build_xpath(&result[count], RPC_UBUS_INVOCATION_XPATH, ubus_invoke_string);
			SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

			rc = sr_val_set_str_data(&result[count], SR_STRING_T, ubus_invoke_string);
			SR_CHECK_RET(rc, cleanup, "sr value set str data: %s", sr_strerror(rc));

			count++;

			rc = sr_val_build_xpath(&result[count], RPC_UBUS_RESPONSE_XPATH, ubus_invoke_string);
			SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

			rc = sr_val_set_str_data(&result[count], SR_STRING_T, result_json_data);
			SR_CHECK_RET(rc, cleanup, "sr value set str data: %s", sr_strerror(rc));

			free(result_json_data);
			result_json_data = NULL;

			count++;
		}
		free(tail_node);
		tail_node = NULL;
	}

	*output_cnt = count;
	*output = result;

	return rc;

cleanup:
	free(tail_node);
	free(result_json_data);
	if (result != NULL) { sr_free_values(result, count); }

	return rc;
}

static int generic_ubus_module_install_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
	int rc = SR_ERR_OK;
	int src = 0;
	char *path_to_module = NULL;
	char command[256+1] = {0};
	char return_message[256+1] = {0};
	sr_val_t *return_values = NULL;
	size_t count = 0;


	// get module name (path included)
	*output_cnt = 0;
	for (size_t i = 0; i < input_cnt; i++)
	{
		memset(return_message, 0, 256+1);
		memset(command, 0, 256+1);

		path_to_module = input[i].data.string_val;
		INF("%s", path_to_module);

		sprintf(command, "sysrepoctl -i -g %s", path_to_module);
		// fork ?
		src = system(command);
		if (src == -1)
		{
			ERR("error while executing `system` command: %d", src);
			rc = SR_ERR_INTERNAL;
			goto cleanup;
		}
		else if (src == 0)
		{
			sprintf(return_message, "Installation of module %s succeeded", path_to_module);
		}
		else
		{
			sprintf(return_message, "Installation of module %s failed, error: %d", path_to_module, src);
		}
		rc = sr_realloc_values(count, count + 2, &return_values);
		SR_CHECK_RET(rc, cleanup, "sr new values error: %s", sr_strerror(rc));

		rc = sr_val_build_xpath(&return_values[count], RPC_MODULE_PATH_XPATH, path_to_module);
		SR_CHECK_RET(rc, cleanup, "sr set xpath for value error: %s", sr_strerror(rc));

		rc = sr_val_set_str_data(&return_values[count], SR_STRING_T, path_to_module);
		SR_CHECK_RET(rc, cleanup, "sr set string value error: %s", sr_strerror(rc));

		count++;

		rc = sr_val_build_xpath(&return_values[count], RPC_MODULE_RESPONSE_XPATH, path_to_module);
		SR_CHECK_RET(rc, cleanup, "sr set xpath for value error: %s", sr_strerror(rc));

		rc = sr_val_set_str_data(&return_values[count], SR_STRING_T, return_message);
		SR_CHECK_RET(rc, cleanup, "sr set string value error: %s", sr_strerror(rc));

		count++;
	}
	*output_cnt = count;
	*output = return_values;

cleanup:
	return rc;
}

// TODO: add RPC support for feature enable disable
static int generic_ubus_feature_update_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
	int rc = SR_ERR_OK;
	int src = 0;
	char *tail_node = NULL;
	uint8_t enable_feature = 0;
	char *yang_module_name = NULL;
	char *feature_name = NULL;
	sr_val_t *return_values = NULL;
	size_t count = 0;

	char command[256+1] = {0};
	char return_message[256+1] = {0};
	char feature_invoke[256+1] = {0};

	uint8_t make_sysrepoctl_call = 0;
	*output_cnt = 0;
	for (size_t i = 0; i < input_cnt; i++)
	{
		rc = xpath_get_tail_node(input[i].xpath, &tail_node);
		CHECK_RET_MSG(rc, cleanup, "get tail node error");

		if (strcmp("module-name", tail_node) == 0)
		{
			yang_module_name = input[i].data.string_val;
		}
		else if (strcmp("feature-name", tail_node) == 0)
		{
			feature_name = input[i].data.string_val;
		}
		else if (strcmp("enable", tail_node) == 0)
		{
			enable_feature = 1;
			make_sysrepoctl_call = 1;
		}
		else if (strcmp("disable", tail_node) == 0)
		{
			enable_feature = 0;
			make_sysrepoctl_call = 1;
		}

		if (make_sysrepoctl_call == 1)
		{
			memset(feature_invoke, 0, 256+1);
			memset(return_message, 0, 256+1);
			memset(command, 0, 256+1);
			if (enable_feature == 1)
			{
				sprintf(command, "sysrepoctl -e %s -m %s", feature_name, yang_module_name);
			}
			else
			{
				sprintf(command, "sysrepoctl -d %s -m %s", feature_name, yang_module_name);
			}
			src = system(command);
			if (src == -1)
			{
				ERR("error while executing `system` command: %d", src);
				rc = SR_ERR_INTERNAL;
				goto cleanup;
			}
			else if (src == 0)
			{
				sprintf(return_message, "%s feature %s in module %s succeeded.",(enable_feature == 1) ? "Enabeling" : "Disabeling", feature_name, yang_module_name);
			}
			else
			{
				sprintf(return_message, "%s feature %s in module %s failed. Error: %d.", (enable_feature == 1) ? "Enabeling" : "Disabeling", feature_name, yang_module_name , src);
			}
			// create response

			sprintf(feature_invoke, "%s %s", yang_module_name, feature_name);


			rc = sr_realloc_values(count, count + 2, &return_values);
			SR_CHECK_RET(rc, cleanup, "sr realloc values error: %s", sr_strerror(rc));

			rc = sr_val_build_xpath(&return_values[count], RPC_FEATURE_INVOCATION_XPATH, feature_invoke);
			SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

			rc = sr_val_set_str_data(&return_values[count], SR_STRING_T, feature_invoke);
			SR_CHECK_RET(rc, cleanup, "sr value set str data: %s", sr_strerror(rc));

			count++;

			rc = sr_val_build_xpath(&return_values[count], RPC_FEATURE_RESPONSE_XPATH, feature_invoke);
			SR_CHECK_RET(rc, cleanup, "sr value set xpath: %s", sr_strerror(rc));

			rc = sr_val_set_str_data(&return_values[count], SR_STRING_T, return_message);
			SR_CHECK_RET(rc, cleanup, "sr value set str data: %s", sr_strerror(rc));

			count++;
			make_sysrepoctl_call = 0;
		}
		free(tail_node);
		tail_node = NULL;
	}

	*output_cnt = count;
	*output = return_values;

	return rc;

cleanup:
	free(tail_node);
	if (return_values != NULL) { sr_free_values(return_values, count); }
	return rc;
}


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

	INF_MSG("Subscribing to ubus call rpc");
	rc = sr_rpc_subscribe(session, "/"YANG_MODEL":ubus-call", generic_ubus_ubus_call_rpc_cb, NULL, SR_SUBSCR_CTX_REUSE, &context->subscription);
	SR_CHECK_RET(rc, cleanup, "rpc subscription error: %s", sr_strerror(rc));

	INF_MSG("Subscribing to module install rpc");
	rc = sr_rpc_subscribe(session, "/"YANG_MODEL":module-install", generic_ubus_module_install_rpc_cb, NULL, SR_SUBSCR_CTX_REUSE, &context->subscription);
	SR_CHECK_RET(rc, cleanup, "rpc subscription error: %s", sr_strerror(rc));

	INF_MSG("Subscribing to feature update rpc");
	rc = sr_rpc_subscribe(session, "/"YANG_MODEL":feature-update", generic_ubus_feature_update_rpc_cb, NULL, SR_SUBSCR_CTX_REUSE, &context->subscription);
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
