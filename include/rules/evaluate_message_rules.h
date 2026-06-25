/**
 * @file evaluate_message_rules.h
 * @brief Header file for evaluating MQTT message payload rules.
 *
 * @defgroup evaluate_message_rules Message rules evaluator
 * @brief Header file for evaluating MQTT message payload rules.
 * @ingroup rules
 *
 * @{
 */

#ifndef EVALUATE_MESSAGE_RULES_H_
#define EVALUATE_MESSAGE_RULES_H_

#include "rules/waf_rules_parse.h"

/**
 * @brief Evaluates message payload rules to detect malicious content or enforce formats.
 * * This function evaluates a given MQTT topic and payload against a defined set of 
 * rules. It checks for topic matches (including MQTT wildcards) and optionally 
 * applies regex pattern matching to the payload. It handles raw byte buffers safely
 * and supports inverted match conditions (e.g., to enforce strict formats like JSON).
 * * @param topic      The MQTT topic the message was published to.
 * @param payload    The raw message payload buffer.
 * @param payloadlen The length of the message payload in bytes.
 * @param rules      A pointer to an array of compiled message rules to evaluate against.
 * @param count      The number of rules in the provided array.
 * * @return 1 if the message is allowed.
 * @return 0 if the message should be dropped.
 * @return -1 if no rules matched (fallback to default WAF policies).
 */
int evaluate_message_rules(const char *topic, const void *payload, int payloadlen, struct message_rule *rules, unsigned count);

#endif

/** @} */