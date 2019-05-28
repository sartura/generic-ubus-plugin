#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "generic_ubus.h"
#include "parse.h"
#include "common.h"

const char *YANG_MODEL = "terastream-generic-ubus";

// TODO: move context related functions to new file
void free_ubus_object(struct ubus_object_s *obj, sr_session_ctx_t *session)
{
	INF("%s", __func__);
	if (NULL == obj) return;
	free(obj->name);
	free(obj->yang_module);

	struct ubus_message_s *msg_p = NULL;
	struct ubus_message_s *msg_n = NULL;
	list_for_each_entry_safe(msg_p, msg_n, &obj->ubus_object_method_list,
							 method_list)
	{
		list_del(&msg_p->method_list);
		free(msg_p->method_name);
		free(msg_p->method_message);
		free(msg_p);
	}

	if (NULL != session && NULL != obj->sd_subscription)
	{
		sr_unsubscribe(session, obj->sd_subscription);
	}
	free(obj);
}

void free_global_ctx(struct global_ctx_s **ctx)
{
	if (NULL != (*ctx)->session && NULL != (*ctx)->subscription)
	{
		sr_unsubscribe((*ctx)->session, (*ctx)->subscription);
		(*ctx)->subscription = NULL;
	}

	ubus_object_t *obj_p = NULL;
	ubus_object_t *obj_n = NULL;
	list_for_each_entry_safe(obj_p, obj_n, &(*ctx)->uo_list, object_list)
	{
		list_del(&obj_p->list);
		free_ubus_object(obj_p, (*ctx)->session);
		obj_p = NULL;
	}

	/* clean startup datastore */
    if (NULL != (*ctx)->session_startup) {
        sr_session_stop((*ctx)->session_startup);
    }
    if (NULL != (*ctx)->connection_startup) {
        sr_disconnect((*ctx)->connection_startup);
	}

	free(*ctx);
	*ctx = NULL;
}

int init_global_ctx(struct global_ctx_s *ctx, sr_session_ctx_t *session)
{
	int rc = SR_ERR_OK;
	if (NULL == ctx)
	{
		return -1;
	}

	ctx->session = session;
	INIT_LIST_HEAD(&ctx->uo_list);

	 /* connect to sysrepo */
    rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &ctx->connection_startup);
    CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

    /* start session */
    rc = sr_session_start(ctx->connection_startup, SR_DS_STARTUP, SR_SESS_CONFIG_ONLY, &ctx->session_startup);
	CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

cleanup:
	return rc;
}

static int generic_ubus_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
	// TODO: add logic
	INF("%s", __func__);
	INF("%s", module_name);
	int rc = SR_ERR_OK;
	struct global_ctx_s *ctx = (struct global_context_s *)private_ctx;

	INF("%d", event);

	if (SR_EV_APPLY == event)
	{
		/* copy running datastore to startup */
        rc = sr_copy_config(ctx->session_startup, YANG_MODEL, SR_DS_RUNNING, SR_DS_STARTUP);
        if (SR_ERR_OK != rc) {
            WRN_MSG("Failed to copy running datastore to startup");
            /* TODO handle this error */
            return rc;
		}
		return SR_ERR_OK;
	}

	rc = parse_config(ctx, module_name, session);
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
	struct global_ctx_s *ctx = calloc(1, sizeof(*ctx));

	rc = init_global_ctx(ctx, session);
	if (rc != 0)
	{
		goto error;
	}
	*private_ctx = ctx;

	INF_MSG("Subcribing to module change");
	rc = sr_module_change_subscribe(session, YANG_MODEL, generic_ubus_change_cb, *private_ctx, 0, SR_SUBSCR_DEFAULT, &ctx->subscription);
	SR_CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));
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

error:
	free_global_ctx(&ctx);
	return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
	INF("%s", __func__);
	INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");

	if (NULL != private_ctx)
	{
		struct global_context_s *ctx = private_ctx;
		free_global_ctx(&ctx);
	}
	SRP_LOG_DBG_MSG("Plugin cleaned-up successfully");
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

int main()
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
			sr_session_stop(session);
		}
		if (NULL != connection) {
			sr_disconnect(connection);
		}
}
#endif
