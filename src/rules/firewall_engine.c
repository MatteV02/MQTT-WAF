/**
 * @file firewall_engine.c
 * @brief Implementation of the core firewall evaluation engine.
 * * This header defines the main entry point for evaluating Mosquitto ACL 
 * events against the configured Web Application Firewall (WAF) rules.
 * @ingroup firewall_engine
 */

#include <regex.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <stdio.h>

#include "rules/waf_rules_parse.h"
#include "rules/evaluate_topic_rules.h"
#include "rules/evaluate_message_rules.h"

int firewall_engine(struct mosquitto_evt_acl_check *acl, struct waf_config *rules) {
    if (!acl || !rules || !acl->client) return 0; 

    if (acl->access == MOSQ_ACL_UNSUBSCRIBE) {
        return 1; // Unsubscribing is generally a safe operation to allow by default
    }
    
    const char *client_id = mosquitto_client_id(acl->client);
    if (!client_id || !acl->topic) return 0;

    int topic_action = evaluate_topic_rules(client_id, acl->access, acl->topic, rules->rules.topic, rules->rules.topic_count);
    
    // If explicit deny, block immediately.
    if (topic_action == 0) {
        return 0; 
    }

    // If topic_action == 1 (allow) or -1 (no match), continue to payload inspection
    if (acl->access == MOSQ_ACL_WRITE) {
        int message_action = evaluate_message_rules(acl->topic, acl->payload, acl->payloadlen, rules->rules.message, rules->rules.message_count);
        if (message_action == 0) return 0; // Explicitly block malicious payload
        if (message_action == 1) return 1; // Explicitly allow based on payload rule
    }

    if (topic_action == 1) {
        return 1;
    }

    // ---------------------------------------------------------
    // 3. DEFAULT POLICIES (Fallback)
    // ---------------------------------------------------------
    const char *default_policy = NULL;
    if (acl->access == MOSQ_ACL_WRITE) {
        default_policy = rules->default_policies.publish;
    } else if (acl->access == MOSQ_ACL_SUBSCRIBE || acl->access == MOSQ_ACL_READ) {
        default_policy = rules->default_policies.subscribe;
    }

    if (default_policy && strcmp(default_policy, "allow") == 0) {
        return 1; // Explicit allow
    }
    
    return 0; // Default deny
}