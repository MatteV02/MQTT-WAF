#ifndef EVALUATE_TOPIC_RULES_H_
#define EVALUATE_TOPIC_RULES_H_

#include "rules/waf_rules_parse.h"

int evaluate_topic_rules(const char *client_id, int access, const char *topic, struct topic_rule *rules, unsigned count);

#endif