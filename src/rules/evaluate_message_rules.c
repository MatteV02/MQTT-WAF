/**
 * @file evaluate_message_rules.c
 * @brief Implementation of the MQTT message payload evaluation logic.
 * @ingroup evaluate_message_rules
 */

#include <stdlib.h>
#include <stdbool.h>
#include <regex.h>
#include <string.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

#include "rules/waf_rules_parse.h"

/*
 * Evaluates message payload rules to detect malicious content or enforce formats.
 * Returns: 1 (allow), 0 (drop), or -1 (no rules matched, use default policy)
 */
int evaluate_message_rules(const char *topic, const void *payload, int payloadlen, struct message_rule *rules, unsigned count) {
    for (unsigned i = 0; i < count; i++) {
        struct message_rule *m_rule = &rules[i];
        
        // A. Check Topic Match
        bool topic_matched = false;
        for (unsigned j = 0; j < m_rule->topics_count; j++) {
            if (!m_rule->topics[j]) continue;

            // Check exact string match
            if (strcmp(topic, m_rule->topics[j]) == 0) {
                topic_matched = true;
                break;
            }
            // Check MQTT wildcard match
            bool mosq_match = false;
            mosquitto_topic_matches_sub(m_rule->topics[j], topic, &mosq_match);
            if (mosq_match) {
                topic_matched = true;
                break;
            }
        }

        if (!topic_matched) continue; // Topic didn't match, move to next rule

        // B. Evaluate Payload against Regex
        if (m_rule->has_payload_regex) {
            bool is_match = false;

            if (payloadlen > 0) {
                if (payload == NULL) {
                    mosquitto_log_printf(MOSQ_LOG_ERR, "WAF: Malformed packet (NULL payload with >0 length).");
                    return 0; // Drop packet
                }

                // MQTT payloads are raw buffers. If the data contains null characters it cannot be interpreted as string, since it should be blocked,
                if (memchr(payload, '\0', payloadlen)) {
                    mosquitto_log_printf(MOSQ_LOG_ERR, "WAF: Payload contains null byte.");
                    return 0;
                }

                // MQTT payloads are raw buffers. Copy and null-terminate for regexec().
                char *payload_str = malloc(payloadlen + 1);
                if (!payload_str) {
                    mosquitto_log_printf(MOSQ_LOG_ERR, "WAF: Memory allocation failed during payload evaluation");
                    return 0; // Fail-safe fallback
                }
                
                memcpy(payload_str, payload, payloadlen);
                payload_str[payloadlen] = '\0';

                // regexec returns 0 for a successful match
                int reg_match = regexec(&m_rule->compiled_payload_regex, payload_str, 0, NULL, 0);
                free(payload_str);

                is_match = (reg_match == 0);
            }

            // Apply invert_match logic (e.g., dropping packets that DO NOT match strict JSON)
            if (m_rule->invert_match) {
                is_match = !is_match;
            }

            // If the payload conditions didn't trigger this rule, skip to the next
            if (!is_match) continue; 
        }

        // C. Enforce Action and Logging if rule triggered
        if (m_rule->log) {
            mosquitto_log_printf(MOSQ_LOG_NOTICE, 
                "WAF [Alert]: Message rule '%s' (ID: %s) triggered on topic '%s'", 
                m_rule->name, m_rule->id, topic);
        }

        if (m_rule->action && strcmp(m_rule->action, "allow") == 0) {
            return 1;
        }
        
        return 0; // Default to drop if action is "drop" or undefined
    }
    
    return -1; // Fallback to default_policies.publish
}