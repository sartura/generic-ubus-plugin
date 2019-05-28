#ifndef _PARSE_H_
#define _PARSE_H_

#include "generic_ubus.h"

int load_startup_datastore(struct global_context_s *);
int parse_config(struct global_context_s *, const char *, sr_session_ctx_t *);

#endif /* _PARSE_H _*/