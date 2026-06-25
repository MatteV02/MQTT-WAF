/**
 * @file firewall_engine.h
 * @brief Implementation of the core firewall evaluation engine.
 * * This header defines the main entry point for evaluating Mosquitto ACL 
 * events against the configured Web Application Firewall (WAF) rules.
 * 
 * @defgroup firewall_engine Firewall Engine
 * @brief Implementation of the core firewall evaluation engine.
 * @ingroup rules
 * 
 * @{
 */

#ifndef FIREWALL_ENGINE_H_
#define FIREWALL_ENGINE_H_

#include <mosquitto_broker.h>
#include "rules/waf_rules_parse.h"

/**
 * @brief firewall_engine evaluates the ACL payload.
 *
 * It checks the client's request against the firewall rules in the following order:
 * 1. Validates the presence of required data (client, rules, topic).
 * 2. Evaluates Topic Rules. Returns immediately if a match dictates an action.
 * 3. Evaluates Message Rules. Returns immediately if a match dictates an action.
 * 4. Applies Default Policies (Publish or Subscribe/Read) if no preceding rules match.
 *
 * @param acl Pointer to the Mosquitto ACL check event.
 * @param rules Pointer to the active WAF configuration ruleset.
 * * @return 1 if the action is explicitly allowed, 0 if denied or explicitly blocked.
 */
int firewall_engine(struct mosquitto_evt_acl_check *acl, struct waf_config *rules);

#endif

/** @} */