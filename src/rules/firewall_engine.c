#include <regex.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <stdio.h>

#include "rules/waf_rules_parse.h"
#include "rules/evaluate_topic_rules.h"

/*
 * firewall_engine evaluates the ACL payload.
 */
int firewall_engine(struct mosquitto_evt_acl_check *acl, struct waf_config *rules) {
    if (!acl || !rules || !acl->client) return 0; 
    
    const char *client_id = mosquitto_client_id(acl->client);
    if (!client_id || !acl->topic) return 0;

    int topic_action = evaluate_topic_rules(client_id, acl->access, acl->topic, rules->rules.topic, rules->rules.topic_count);
    
    if (topic_action != -1) {
        return topic_action; 
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