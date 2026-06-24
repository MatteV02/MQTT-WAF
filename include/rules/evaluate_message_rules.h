#ifndef EVALUATE_MESSAGE_RULES_H_
#define EVALUATE_MESSAGE_RULES_H_

#include "rules/waf_rules_parse.h"

int evaluate_message_rules(const char *topic, const void *payload, int payloadlen, struct message_rule *rules, unsigned count);

#endif