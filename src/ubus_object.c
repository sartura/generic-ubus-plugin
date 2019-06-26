/*
 * @file ubus_object.c
 * @author Luka Paulic <luka.paulic@sartura.hr>
 *
 * @brief Implements the ubus object getters and setters. Also provides ubus
 *        object constructor and destructor as well as functions for subscribing
 *        unsubscribing to sysrepo events. Provides getters for ubus methods for
 *        a given ubus object.
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
#include "sysrepo.h"

#include "ubus_object.h"

/*=========================Function definitions===============================*/

/*
 * @brief Allocates memory for an ubus_object structure and initializes
 *        all pointers to NULL.
 *
 * @param[in/out] ubus_object pointer that points to a newly allocated
 *                structure.
 *
 * @return error code.
 *
*/
int ubus_object_create(ubus_object_t **ubus_object)
{
    int rc = SR_ERR_OK;

    *ubus_object = calloc(1, sizeof(ubus_object_t));
    CHECK_NULL_MSG(*ubus_object, &rc, cleanup, "return argument ubus_object is null");

    (*ubus_object)->name = NULL;
    (*ubus_object)->yang_module = NULL;
    (*ubus_object)->state_data_subscription = NULL;

    (*ubus_object)->libyang_ctx = NULL;
    (*ubus_object)->libyang_module = NULL;

    INIT_LIST_HEAD(&((*ubus_object)->ubus_method_list));

    return rc;

cleanup:
    free(ubus_object);
    return rc;
}

/*
 * @brief Setter for ubus object name.
 *
 * @param[in] ubus_object structure to be modified.
 * @param[in] name ubus object name to be set.
 *
 * @return error code.
 *
 */
int ubus_object_set_name(ubus_object_t *ubus_object, const char *name)
{
    int rc = SR_ERR_OK;
    char *name_local = NULL;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(name, &rc, cleanup, "input argument name is null");

    name_local = calloc(strlen(name)+1, sizeof(char));
    CHECK_NULL_MSG(name_local, &rc, cleanup, "memory allocation for name failed");

    strncpy(name_local, name, strlen(name));

    if (ubus_object->name != NULL) free(ubus_object->name);
    ubus_object->name = name_local;

    return rc;

cleanup:
    free(name_local);
    return rc;
}

/*
 * @brief Setter for ubus object YANG module.
 *
 * @param[in] ubus_object structure to be modified.
 * @param[in] yang_module ubus object YANG module to be set.
 *
 * @return error code.
 *
 */
int ubus_object_set_yang_module(ubus_object_t *ubus_object, const char *yang_module)
{
    int rc = SR_ERR_OK;
    char *yang_module_local = NULL;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(yang_module, &rc, cleanup, "input argument yang_module is null");

    yang_module_local = calloc(strlen(yang_module)+1, sizeof(char));
    CHECK_NULL_MSG(yang_module_local, &rc, cleanup, "memory allocation for yang_module failed");

    strncpy(yang_module_local, yang_module, strlen(yang_module));

    if (ubus_object->yang_module != NULL) free(ubus_object->yang_module);
    ubus_object->yang_module = yang_module_local;

    return rc;

cleanup:
    free(yang_module_local);
    return rc;
}

/*
 * @brief Subscribes to sysrepo for the state data requests.
 *
 * @param[in] session session context for subscribing to sysrepo state data.
 * @param[in] private_ctx context to pass to the callback function.
 * @param[in] ubus_object ubus object for which state date to subscribe to.
 * @param[in] f function pointer to the callback to be called.
 *
 * @return error code.
*/
int ubus_object_state_data_subscribe(sr_session_ctx_t *session, void *private_ctx, ubus_object_t *ubus_object, int (*f)(const char *, sr_val_t **, size_t *, uint64_t, const char *, void *))
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(private_ctx, &rc, cleanup, "input argument private_ctx is null");
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(session, &rc, cleanup, "input argument session is null");
    CHECK_NULL_MSG(f, &rc, cleanup, "input argument f is null");

    char xpath[256 + 1] = {0};
    snprintf(xpath, strlen(ubus_object->yang_module) + 4, "/%s:*", ubus_object->yang_module);

    INF_MSG("Subscribing to operational");
	rc = sr_dp_get_items_subscribe(session,
								   xpath,
								   f,
								   private_ctx,
								   SR_SUBSCR_CTX_REUSE,
								   &ubus_object->state_data_subscription);
    SR_CHECK_RET(rc, cleanup, "dp subscription: %s", sr_strerror(rc));
cleanup:
    return rc;
}

/*
 * @brief Enables the feature in the libyang module for a given object.
 *
 * @param[in] ubus_object ubus object for which the feature needs to be
 *            enabled.
 * @param[in] feature_name feature to be enabled.
 *
 * @return error code.
*/
int ubus_object_libyang_feature_enable(ubus_object_t *ubus_object, const char *feature_name)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(feature_name, &rc, cleanup, "input argument feature_name is null");

    int lrc = lys_features_enable(ubus_object->libyang_module, feature_name);
    if (lrc != 0)
    {
        rc = SR_ERR_INTERNAL;
        ERR("libyang feature enable error: %d", lrc);
    }

cleanup:
    return rc;
}

/*
 * @brief Disable the feature in the libyang module for a given object.
 *
 * @param[in] ubus_object ubus object for which the feature needs to be
 *            disable.
 * @param[in] feature_name feature to be disabled.
 *
 * @return error code.
*/
int ubus_object_libyang_feature_disable(ubus_object_t *ubus_object, const char *feature_name)
{
        int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(feature_name, &rc, cleanup, "input argument feature_name is null");

    int lrc = lys_features_disable(ubus_object->libyang_module, feature_name);
    if (lrc != 0)
    {
        rc = SR_ERR_INTERNAL;
        ERR("libyang feature disable error: %d", lrc);
    }

cleanup:
    return rc;
}

/*
 * @brief Adds an ubus method to the ubus object structure.
 *
 * @param[in] ubus_object ubus object that contains the ubus method.
 * @param[in] ubus_method ubus methdod to be added to the ubus object
 *            method list.
 *
 * @return error code.
*/
int ubus_object_add_method(ubus_object_t *ubus_object, ubus_method_t *ubus_method)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_method, &rc, cleanup, "input argument ubus_method is null");

    list_add(&ubus_method->list, &ubus_object->ubus_method_list);

cleanup:
    return rc;
}

/*
 * @brief Removes an ubus method from the ubus object method list and frees the
 *        memory allocated for the ubus method structure.
 *
 * @param[in] ubus_object ubus object storing the ubus mathod.
 * @param[in] method_name name of the method to be deleted.
 *
 * @return error code.
 *
*/
int ubus_object_delete_method(ubus_object_t *ubus_object, const char *method_name)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(method_name, &rc, cleanup, "input argument method_name is null");

    ubus_method_t *ubus_method = NULL;
    rc = ubus_object_get_method(ubus_object, &ubus_method, method_name);
    CHECK_RET(rc, cleanup, "ubus method %s not found", method_name);

    list_del(&ubus_method->list);
    ubus_method_destroy(&ubus_method);

cleanup:
    return rc;
}

/*
 * @brief Removes all ubus methods from the ubus object method list and frees
 *        the memory allocated for the ubus method structures.
 *
 * @param[in] ubus_object ubus object storing the ubus mathods.
 *
 * @return error code.
 *
*/
int ubus_object_delete_all_methods(ubus_object_t *ubus_object)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    ubus_method_t *ubus_method_p = NULL;
    ubus_method_t *ubus_method_n = NULL;
    list_for_each_entry_safe(ubus_method_p, ubus_method_n, &ubus_object->ubus_method_list, list)
    {
        list_del(&ubus_method_p->list);
        ubus_method_destroy(&ubus_method_p);
    }

cleanup:
    return rc;
}

/*
 * @brief Getter for the ubus object name.
 *
 * @param[in] ubus_object ubus object holding the data.
 * @param[out] name ubus object name to be returned.
 *
 * @return error code.
*/
int ubus_object_get_name(ubus_object_t *ubus_object, char **name)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_object->name, &rc, cleanup, "ubus_object name is null");

    *name = ubus_object->name;

cleanup:
    return rc;
}

/*
 * @brief Getter for the ubus object YANG module.
 *
 * @param[in] ubus_object ubus object holding the data.
 * @param[out] yang_module ubus object yang_module to be returned.
 *
 * @return error code.
*/
int ubus_object_get_yang_module(ubus_object_t *ubus_object, char **yang_module)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_object->yang_module, &rc, cleanup, "ubus_object yang_module is null");


    *yang_module = ubus_object->yang_module;

cleanup:
    return rc;
}

/*
 * @brief Getter for the ubus object method.
 *
 * @param[in] ubus_object ubus object holding the data.
 * @param[in] method_name name of the method to be returned.
 * @param[out] method ubus object yang_module to be returned.
 *
 * @return error code.
*/
int ubus_object_get_method(ubus_object_t *ubus_object, ubus_method_t **ubus_method, const char *method_name)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");

    ubus_method_t *ubus_method_local = NULL;
    list_for_each_entry(ubus_method_local, &ubus_object->ubus_method_list, list)
    {
        if (strncmp(ubus_method_local->name, method_name, strlen(ubus_method_local->name)) == 0)
        {
            *ubus_method = ubus_method_local;
            return rc;
        }
    }
    ERR("method %s not found", method_name);
    rc = SR_ERR_INTERNAL;

cleanup:
    return rc;
}

/*
 * @brief Removes all subscriptions for a given ubus object.
 *
 * @pram[in] session session context for unsubscribing from a callback function.
 * @param[in] ubus_object ubus object for which to unsubscribe from callbacks.
 *
 * @return error code.
 *
*/
int ubus_object_unsubscribe(sr_session_ctx_t *session, ubus_object_t *ubus_object)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(session, &rc, cleanup, "input argument session is null");

    if (ubus_object->state_data_subscription != NULL)
    {
        INF_MSG("Unsubscribing from operational");
        rc = sr_unsubscribe(session, ubus_object->state_data_subscription);
        SR_CHECK_RET(rc, cleanup, "sr_unsubscribe: %s", sr_strerror(rc));

        ubus_object->state_data_subscription = NULL;
    }

cleanup:
    return rc;
}

/*
 * @brief Initializes necessary libyang data for a ubus object. Creates
 *        libyang context and module structures. Enables already enabled
 *        features.
 *
 * @param[in] ubus_object for which libyang data needs to be initialized.
 * @param[in] session session context to get all modules registered in sysrepo.
 *
 * @return error code.
 *
*/
int ubus_object_init_libyang_data(ubus_object_t *ubus_object, sr_session_ctx_t *session)
{
    int rc = SR_ERR_OK;
    struct ly_ctx *libyang_ctx = NULL;
    struct lys_module *libyang_module = NULL;
    char *sysrepo_schema = NULL;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input ubus_object is null");
    CHECK_NULL_MSG(session, &rc, cleanup, "input session is null");

    if (ubus_object->libyang_ctx != NULL) { ly_ctx_destroy(ubus_object->libyang_ctx, NULL); }
    // TODO : ly_ctx and module here
    ubus_object->libyang_ctx = NULL;
    libyang_ctx = ly_ctx_new(NULL, LY_CTX_ALLIMPLEMENTED );
    CHECK_NULL_MSG(libyang_ctx, &rc, cleanup, "libyang_ctx is null");

    rc = sr_get_schema(session, ubus_object->yang_module, NULL, NULL, SR_SCHEMA_YANG, &sysrepo_schema);
    CHECK_RET_MSG(rc, cleanup, "get schema from sysrepo error");

    libyang_module = (struct lys_module *) lys_parse_mem(libyang_ctx, sysrepo_schema, LYS_IN_YANG);
    CHECK_NULL_MSG(libyang_module, &rc, cleanup, "ly module  is null");

    sr_schema_t *schemas = NULL;
	size_t schema_cnt = 0;

    ubus_object->libyang_ctx = libyang_ctx;
    ubus_object->libyang_module = libyang_module;

	rc = sr_list_schemas(session, &schemas, &schema_cnt);
	CHECK_RET(rc, cleanup, "failed sr_list_schemas: %s", sr_strerror(rc));
	for (size_t s = 0; s < schema_cnt; s++) {
		if (0 == strcmp(ubus_object->yang_module, schemas[s].module_name)) {
			for (size_t i = 0; i < schemas[s].enabled_feature_cnt; i++) {
                INF("FEATURE: %s", schemas[s].enabled_features[i]);
				rc = ubus_object_libyang_feature_enable(ubus_object, schemas[s].enabled_features[i]);
                CHECK_RET_MSG(rc, cleanup, "ubus object feature enable");
			}
		}
	}

    free(sysrepo_schema);
    if (NULL != schemas && schema_cnt > 0) {
		sr_free_schemas(schemas, schema_cnt);
	}

    return rc;

cleanup:

    free(sysrepo_schema);
    if (NULL != schemas && schema_cnt > 0) {
		sr_free_schemas(schemas, schema_cnt);
	}

    if (libyang_ctx != NULL)
    {
        ly_ctx_destroy(libyang_ctx, NULL);
    }

    return rc;
}

/*
 * @brief Getter for the ubus object libyang schema.
 *
 * @param[in] ubus_object ubus object holding the data.
 * @param[out] module libyang module for ubus object to be returned.
 *
 * @return error code.
*/
int ubus_object_get_libyang_schema(ubus_object_t *ubus_object, struct lys_module **module)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input argument ubus_object is null");
    CHECK_NULL_MSG(ubus_object->libyang_ctx, &rc, cleanup, "ubus_object libyang_ctx is null");


    *module = ubus_object->libyang_module;

cleanup:
    return rc;
}

/*
 * @brief Cleans the libyang context structure.
 *
 * @param[in] ubus_object ubus object for which to cleanup the libyang context.
 *
 * @return error code.
*/
int ubus_object_clean_libyang_data(ubus_object_t *ubus_object)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_MSG(ubus_object, &rc, cleanup, "input ubus_object is null");

    ly_ctx_destroy(ubus_object->libyang_ctx, NULL);

cleanup:
    return rc;
}

/*
 * @brief Cleans up ubus object structure. Unsubscribes from all sysrepo
 *        state date callback functions. Frees all methods in the method list.
 *        Sets the pointer to NULL after the cleanup.
 *
 * @param[in] ubus_object ubus object to be freed.
*/
void ubus_object_destroy(ubus_object_t **ubus_object)
{
    if (*ubus_object != NULL)
    {
        free((*ubus_object)->name);
        free((*ubus_object)->yang_module);


        int rc = ubus_object_clean_libyang_data(*ubus_object);
        CHECK_RET_MSG(rc, cleanup, "clean ubus object libyang ");
        rc = ubus_object_delete_all_methods(*ubus_object);
        CHECK_RET_MSG(rc , cleanup, "ubus object delete all methods error");
    }
cleanup:
    free(*ubus_object);
    *ubus_object = NULL;
}