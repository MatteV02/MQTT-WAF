#ifndef FIREWALL_ENGINE_H_
#define FIREWALL_ENGINE_H_

#include <mosquitto_broker.h>
#include "rules/waf_rules_parse.h"

int firewall_engine(struct mosquitto_evt_acl_check *acl, struct waf_config *rules);

#endif