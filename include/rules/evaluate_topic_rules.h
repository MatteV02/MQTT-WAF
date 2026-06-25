/**
 * @file evaluate_topic_rules.h
 * @brief Header file for evaluating topic-based firewall rules.
 * 
 * @defgroup evaluate_topic_rules Topic Rules Evaluator
 * @brief Header file for evaluating topic-based firewall rules.
 * @ingroup rules
 *
 * @{
 */

#ifndef EVALUATE_TOPIC_RULES_H_
#define EVALUATE_TOPIC_RULES_H_

#include "rules/waf_rules_parse.h"

/**
 * @brief Evaluates topic rules based on the client's access type (Publish/Subscribe).
 * * This function processes a set of firewall rules against a client's request to
 * publish or subscribe to a specific topic. It performs regex matching on the 
 * client ID and handles both exact topic matches and Mosquitto sub-matches 
 * (wildcards).
 *
 * @param client_id The unique identifier of the connected MQTT client.
 * @param access    The requested access level (e.g., MOSQ_ACL_WRITE, MOSQ_ACL_SUBSCRIBE).
 * @param topic     The target MQTT topic string.
 * @param rules     Pointer to the array of loaded topic rules.
 * @param count     The total number of rules in the array.
 *
 * @return 1 if a matching rule explicitly allows the action.
 * @return 0 if a matching rule explicitly drops the action.
 * @return -1 if no rule matches (fallback to the default policy).
 */
int evaluate_topic_rules(const char *client_id, int access, const char *topic, struct topic_rule *rules, unsigned count);

#endif

/** @} */