#include <stdbool.h>
#include <regex.h>
#include <string.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

#include "rules/waf_rules_parse.h"

/*
 * Evaluates topic rules based on whether the client is Publishing or Subscribing.
 */
int evaluate_topic_rules(const char *client_id, int access, const char *topic, struct topic_rule *rules, unsigned count) {
    for (unsigned i = 0; i < count; i++) {
        struct topic_rule *t_rule = &rules[i];
        
        // A. Check Client ID Match
        if (t_rule->has_client_id_regex) {
            int reg_match = regexec(&t_rule->compiled_client_id_regex, client_id, 0, NULL, 0);
            if (reg_match) continue; // Client ID didn't match, move to next rule
        }

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
            if (t_rule->action && strcmp(t_rule->action, "allow") == 0) return 1;
            
            return 0; 
        }
    }
    return -1; // Fallback to default policy
}