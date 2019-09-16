/*
 * @file main.c
 * @author Luka Paulic <luka.paulic@sartura.hr>
 *
 * @brief Main function that supplies the plugin initialization and cleanup
 * 		  functions. Additionally if the code is not compiled to run as
 *a plugin a main function for creating a session and connection to sysrepo is
 *supplied.
 *
 * @copyright
 * Copyright (C) 2019 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*=========================Includes===========================================*/
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sysrepo.h"

#include "common.h"
#include "context.h"
#include "generic_ubus.h"
#include "ubus_call.h"

/*=========================Function definitions===============================*/

/*
 * @brief Callback for initializing the plugin. Establishes a connection
 *  	  to the startup datastore and syncs with the running data store.
 * 		  Subscribes to generic ubus YANG module chagne, feature enable,
 * 		  ubus call RPC and module install RPC.
 *
 * @param[in] session session context used for subscribiscions.
 * @param[out] private_ctx context to be used in callback.
 *
 * @return error code.
 *
 */
int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx) {
  INF("%s", __func__);

  int rc = SR_ERR_OK;
  context_t *context = NULL;
  rc = context_create(&context);
  SR_CHECK_RET(rc, cleanup, "%s: context_create: %s", __func__, sr_strerror);

  rc = context_set_session(context, session);
  SR_CHECK_RET(rc, cleanup, "%s: context_create: %s", __func__, sr_strerror);

  *private_ctx = context;

  sr_conn_ctx_t *startup_connection = NULL;
  rc = sr_connect(SR_CONN_DEFAULT, &startup_connection);
  CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

  sr_session_ctx_t *startup_session = NULL;
  rc = sr_session_start(startup_connection, SR_DS_STARTUP, &startup_session);
  CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

  rc = context_set_startup_connection(context, startup_connection);
  SR_CHECK_RET(rc, cleanup, "context error: %s", sr_strerror(rc));

  rc = context_set_startup_session(context, startup_session);
  SR_CHECK_RET(rc, cleanup, "context error: %s", sr_strerror(rc));

  // load startup datastore
  rc = generic_ubus_load_startup_datastore(context);
  SR_CHECK_RET(rc, cleanup, "context error: %s", sr_strerror(rc));

  INF_MSG("Subcribing to module change");
  rc = sr_module_change_subscribe(session, YANG_MODEL, NULL,
                                  generic_ubus_change_cb, *private_ctx, 0,
                                  SR_SUBSCR_DEFAULT, &context->subscription);
  SR_CHECK_RET(rc, cleanup, "initialization error: %s", sr_strerror(rc));

  INF_MSG("Subscribing to ubus call rpc");
  rc = sr_rpc_subscribe(session, "/" YANG_MODEL ":ubus-call",
                        generic_ubus_ubus_call_rpc_cb, *private_ctx, 0,
                        SR_SUBSCR_CTX_REUSE, &context->subscription);
  SR_CHECK_RET(rc, cleanup, "rpc subscription error: %s", sr_strerror(rc));

  INF_MSG("Subscribing to module install rpc");
  rc = sr_rpc_subscribe(session, "/" YANG_MODEL ":module-install",
                        generic_ubus_module_install_rpc_cb, NULL, 0,
                        SR_SUBSCR_CTX_REUSE, &context->subscription);
  SR_CHECK_RET(rc, cleanup, "rpc subscription error: %s", sr_strerror(rc));

  INF_MSG("Subscribing to feature update rpc");
  rc = sr_rpc_subscribe(session, "/" YANG_MODEL ":feature-update",
                        generic_ubus_feature_update_rpc_cb, NULL, 0,
                        SR_SUBSCR_CTX_REUSE, &context->subscription);
  SR_CHECK_RET(rc, cleanup, "rpc subscription error: %s", sr_strerror(rc));

  /*
    INF_MSG("Subscribing to feature change");
    rc = sr_feature_enable_subscribe(session, generic_ubus_feature_cb,
                                     *private_ctx, SR_SUBSCR_CTX_REUSE,
                                     &context->subscription);
    SR_CHECK_RET(rc, cleanup, "feature subscription error: %s",
    sr_strerror(rc));
  */
  INF_MSG("Succesfull init");
  return SR_ERR_OK;

cleanup:
  context_destroy(&context);
  return rc;
}

/*
 * @brief Cleans the private context passed to the callbacks and unsubscribes
 * 		  from all subscriptions.
 *
 * @param[in] session session context for unsubscribing.
 * @param[in] private_ctx context to be released fro memory.
 *
 */
void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx) {
  INF("%s", __func__);
  INF("Plugin cleanup called, private_ctx is %s available.",
      private_ctx ? "" : "not");

  if (NULL != private_ctx) {
    context_t *context = private_ctx;
    context_destroy(&context);
  }
  INF_MSG("Plugin cleaned-up successfully");
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

/*
 * @brief Termination signal handeling
 *
 * @param[in] signum signal identifier.
 *
 * @note signum is not used.
 */
static void sigint_handler(__attribute__((unused)) int signum) {
  INF_MSG("Sigint called, exiting...");
  exit_application = 1;
}

/*
 * @brief Initializes the connection to sysrepo and initializes the plugin.
 * 		  When the program is interupted the cleanup code is called.
 *
 * @return error code.
 *
 */
int main(void) {
  INF_MSG("Plugin application mode initialized");
  sr_conn_ctx_t *connection = NULL;
  sr_session_ctx_t *session = NULL;
  void *private_ctx = NULL;
  int rc = SR_ERR_OK;

  /* connect to sysrepo */
  INF_MSG("Connecting to sysrepo ...");
  rc = sr_connect(SR_CONN_DEFAULT, &connection);
  SR_CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

  ENABLE_LOGGING(SR_LL_DBG);

  /* start session */
  INF_MSG("Starting session ...");
  rc = sr_session_start(connection, SR_DS_RUNNING, &session);
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
    if (rc != SR_ERR_OK)
      INF("cleanup: %s", sr_strerror(rc));
  }
  if (NULL != connection) {
    sr_disconnect(connection);
  }
  return rc;
}
#endif
