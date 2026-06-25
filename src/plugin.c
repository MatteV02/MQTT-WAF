/**
 * @file plugin.c
 * @brief Main entry point for the Mosquitto WAF and Logger plugin.
 *
 * This file contains the core lifecycle functions and ACL callback required 
 * to interface with the Mosquitto broker, parse WAF rules, and handle 
 * message forwarding and logging.
 *
 * @ingroup units Units
 */

#include <string.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

#include "bridge/message_logger.h"
#include "bridge/message_forwarder.h"
#include "bridge/settings.h"
#include "rules/waf_rules_parse.h"
#include "rules/firewall_engine.h"

static mosquitto_plugin_id_t *plugin_id = NULL;
static struct mosquitto *ext_client = NULL;

// Global pointer for our parsed settings
static struct settings *plugin_config = NULL;

// Global pointer for our WAF rules
static struct waf_config *waf_rules = NULL;

int callback_acl_check(int event, void *event_data, void *userdata) {
    struct mosquitto_evt_acl_check *msg = event_data;

    // Allow locally injected plugins to bypass WAF logic
    if (msg->client == NULL) {
        return MOSQ_ERR_SUCCESS; 
    }

    const char *client_id = mosquitto_client_id(msg->client);
    const char *topic = msg->topic ? msg->topic : "UNKNOWN";

    // 1. Run the request through the WAF engine FIRST
    int waf_decision = firewall_engine(msg, waf_rules);

    if (waf_decision == 0) {
        // WAF Denied: Destroy the packet immediately.
        mosquitto_log_printf(MOSQ_LOG_WARNING, 
            "WAF [DENY]: Dropped packet (Access: %d) from Client: '%s' on Topic: '%s'", 
            msg->access, client_id, topic);
            
        return MOSQ_ERR_ACL_DENIED; 
    } 
    
    // 2. WAF Approved
    mosquitto_log_printf(MOSQ_LOG_INFO, 
        "WAF [ALLOW]: Approved packet (Access: %d) from Client: '%s' on Topic: '%s'", 
        msg->access, client_id, topic);
        
    // 3. Delegate to Bridge Logic ONLY if it's a valid, approved packet
    if (msg->access == MOSQ_ACL_SUBSCRIBE) {
        // forward a subscription
        if (ext_client) {
            subscription_forward(ext_client, topic);
        }
    } else if (msg->access == MOSQ_ACL_WRITE) {
        // forward the published message
        if (ext_client) {
            publish_forward(ext_client, msg);
        }
    }

    // 4. Finally, grant actual access in the broker
    return MOSQ_ERR_SUCCESS; 
}

/* The broker calls this to check if the plugin is compatible */
int mosquitto_plugin_version(int supported_version_count, const int *supported_versions) {
    for (int i = 0; i < supported_version_count; i++) {
        if (supported_versions[i] == 5) {
            return 5;
        }
    }
    return -1;
}

/* Called when the plugin is loaded */
int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count) {
    plugin_id = identifier;
    
    // 1. Determine the path to the YAML config file
    const char *config_path = "/etc/mosquitto/plugin_config.yaml"; // Default fallback path
    const char *waf_path = "/etc/mosquitto/waf_rules.yaml";        // WAF fallback path
    
    // Look for a custom path passed from mosquitto.conf via `plugin_opt_config_path ...`
    for (int i = 0; i < opt_count; i++) {
        if (strcmp(opts[i].key, "config_path") == 0) {
            config_path = opts[i].value;
        } else if (strcmp(opts[i].key, "waf_rules_path") == 0) {
            waf_path = opts[i].value;
        }
    }

    // 2. Parse the settings
    plugin_config = parse_settings(config_path);
    if (!plugin_config) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to parse YAML config at %s", config_path);
        return MOSQ_ERR_UNKNOWN;
    }

    waf_rules = load_waf_rules(waf_path);
    if (!waf_rules) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "WAF Plugin: FAILED to load WAF rules at %s. Aborting start to maintain security.", waf_path);
        free_settings(plugin_config);
        plugin_config = NULL;
        return MOSQ_ERR_UNKNOWN; // Reject plugin load if WAF fails (fail-closed)
    }

    // 3. Initialize the logger
    int status = start_logger();
    if (status) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Cannot open /tmp/mqtt_packets.log");
        free_settings(plugin_config);
        free_waf_rules(waf_rules);
        plugin_config = NULL;
        return MOSQ_ERR_UNKNOWN;
    }

    print_waf_rules(waf_rules);

    // 4. Initialize the forwarder using parsed YAML settings
    ext_client = start_forwarder(
        plugin_config->ext_client_id, 
        plugin_config->ext_broker_host, 
        plugin_config->ext_broker_port
    );
    
    if (!ext_client) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to init connection to external broker");
        // TODO add a background retry logic to use the local broker as cache and then send message to the remote broker
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "Logger Plugin: Initialized successfully using %s", config_path);

    // Register the callback to intercept published messages
    mosquitto_callback_register(plugin_id, MOSQ_EVT_ACL_CHECK, callback_acl_check, NULL, NULL);
    return MOSQ_ERR_SUCCESS;
}

/* Called when the broker is shutting down */
int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
    // Unregister the callback
    mosquitto_callback_unregister(plugin_id, MOSQ_EVT_ACL_CHECK, callback_acl_check, NULL);

    stop_forwarder(ext_client);
    stop_logger();
    
    // Clean up our parsed YAML settings from memory
    if (plugin_config) {
        free_settings(plugin_config);
        plugin_config = NULL;
    }

    // Clean up our WAF allocations
    if (waf_rules) {
        free_waf_rules(waf_rules);
        waf_rules = NULL;
    }
    
    mosquitto_log_printf(MOSQ_LOG_INFO, "Logger Plugin: Cleaned up.");
    return MOSQ_ERR_SUCCESS;
}