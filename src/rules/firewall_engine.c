#include <regex.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <stdio.h>

#include "rules/waf_rules_parse.h"

/*
 * Evaluates topic rules based on whether the client is Publishing or Subscribing.
 */
int evaluate_topic_rules(const char *client_id, int access, const char *topic, struct topic_rule *rules, unsigned count) {
    for (unsigned i = 0; i < count; i++) {
        struct topic_rule *t_rule = &rules[i];
        
        // A. Check Client ID Match
        regex_t regex;
        if (regcomp(&regex, t_rule->client_id_regex, REG_EXTENDED | REG_NOSUB) != 0) continue;
        int reg_match = regexec(&regex, client_id, 0, NULL, 0);
        regfree(&regex);
        
        if (reg_match != 0) continue; // Client ID didn't match

        // B. Check Topic Match based on the Access Type (Publish vs Subscribe)
        bool topic_matched = false;
        char **topic_array = NULL;
        unsigned topic_count = 0;

        if (access == MOSQ_ACL_WRITE) {
            topic_array = t_rule->permissions.publish;
            topic_count = t_rule->permissions.publish_count;
        } else if (access == MOSQ_ACL_SUBSCRIBE || access == MOSQ_ACL_READ) {
            topic_array = t_rule->permissions.subscribe;
            topic_count = t_rule->permissions.subscribe_count;
        }

        for (unsigned j = 0; j < topic_count; j++) {
            if (strcmp(topic, topic_array[j]) == 0) {
                topic_matched = true;
                break;
            }
            bool mosq_match = false;
            mosquitto_topic_matches_sub(topic_array[j], topic, &mosq_match);
            if (mosq_match) {
                topic_matched = true;
                break;
            }
        }

        // C. Enforce Action if the topic matched
        if (topic_matched) {
            if (t_rule->action && strcmp(t_rule->action, "drop") == 0) return 0;
            if (t_rule->action && strcmp(t_rule->action, "allow") == 0) return 1;
        }
    }
    return -1; // Fallback to default policy
}

/*
 * firewall_engine evaluates the ACL payload.
 */
int firewall_engine(struct mosquitto_evt_acl_check *acl, struct waf_config *rules) {
    if (!acl || !rules || !acl->client) return 0; 
    
    const char *client_id = mosquitto_client_id(acl->client);
    if (!client_id || !acl->topic) return 0;

    // ---------------------------------------------------------
    // 1. RATE LIMITING & PAYLOAD RULES (Placeholders)
    // ---------------------------------------------------------
    // Note: The payload is available in `acl->payload` during MOSQ_ACL_WRITE!
    // if (acl->access == MOSQ_ACL_WRITE && !evaluate_payload(acl->topic, acl->payload, acl->payloadlen, ...)) return 0;

    // ---------------------------------------------------------
    // 2. TOPIC RULES (ACL Verification)
    // ---------------------------------------------------------
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