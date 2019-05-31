#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "context.h"
#include "generic_ubus.h"
#include "common.h"


static int generic_ubus_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
	// TODO: add logic
	INF("%s", __func__);
	INF("%s", module_name);
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
