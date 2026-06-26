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
#include <stdio.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

#include "bridge/message_logger.h"
#include "bridge/message_forwarder.h"
#include "bridge/settings.h"
#include "rules/waf_rules_parse.h"
#include "rules/firewall_engine.h"

/**
 * @brief Unique identifier for this plugin instance.
 * Assigned by the Mosquitto broker during initialization.
 */
static mosquitto_plugin_id_t *plugin_id = NULL;

/**
 * @brief External Mosquitto client used for forwarding approved publish messages.
 */
static struct mosquitto *ext_client_pub = NULL;

/**
 * @brief External Mosquitto client used for forwarding approved subscription messages.
 */
static struct mosquitto *ext_client_sub = NULL;

/**
 * @brief Global pointer for parsed YAML plugin settings.
 */
static struct settings *plugin_config = NULL;

/**
 * @brief Global pointer for the parsed Web Application Firewall (WAF) rules.
 */
static struct waf_config *waf_rules = NULL;

/**
 * @brief Callback function triggered for MQTT ACL checks.
 *
 * Evaluates incoming requests against the Web Application Firewall (WAF) engine.
 * If approved, forwards the message or subscription via the bridge logic and grants access.
 * Locally injected plugins bypass this WAF logic entirely.
 *
 * @param event The event type triggered (expected to be MOSQ_EVT_ACL_CHECK).
 * @param event_data Pointer to a `mosquitto_evt_acl_check` structure containing message details.
 * @param userdata Custom user data passed during callback registration (unused).
 * @return `MOSQ_ERR_SUCCESS` if access is granted, `MOSQ_ERR_ACL_DENIED` if blocked by the WAF.
 */
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

    log_message(msg);

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
        if (ext_client_sub) {
            subscription_forward(ext_client_sub, topic);
        }
    } else if (msg->access == MOSQ_ACL_WRITE) {
        // forward the published message
        if (ext_client_pub) {
            publish_forward(ext_client_pub, msg);
        }
    }

    // 4. Finally, grant actual access in the broker
    return MOSQ_ERR_SUCCESS; 
}

/**
 * @brief Verifies plugin compatibility with the running broker version.
 *
 * The broker calls this during the plugin load phase to ensure API compatibility.
 * * @param supported_version_count Number of API versions supported by the broker.
 * @param supported_versions Array of supported API version integers.
 * @return The agreed version number (5), or -1 if no compatible version is found.
 */
int mosquitto_plugin_version(int supported_version_count, const int *supported_versions) {
    for (int i = 0; i < supported_version_count; i++) {
        if (supported_versions[i] == 5) {
            return 5;
        }
    }
    return -1;
}

/**
 * @brief Verifies plugin compatibility with the running broker version.
 *
 * The broker calls this during the plugin load phase to ensure API compatibility.
 * * @param supported_version_count Number of API versions supported by the broker.
 * @param supported_versions Array of supported API version integers.
 * @return The agreed version number (5), or -1 if no compatible version is found.
 */
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

    // 4. Initialize the distinct forwarders
    char pub_id[256];
    char sub_id[256];
    snprintf(pub_id, sizeof(pub_id), "%s_pub", plugin_config->ext_client_id);
    snprintf(sub_id, sizeof(sub_id), "%s_sub", plugin_config->ext_client_id);

    // Explicitly start the Publisher
    ext_client_pub = start_publish_forwarder(
        pub_id, 
        plugin_config->ext_broker_host, 
        plugin_config->ext_broker_port
    );
    
    // Explicitly start the Subscriber
    ext_client_sub = start_subscription_forwarder(
        sub_id, 
        plugin_config->ext_broker_host, 
        plugin_config->ext_broker_port
    );
    
    if (!ext_client_pub || !ext_client_sub) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to init connection to external broker");
        // TODO add a background retry logic to use the local broker as cache and then send message to the remote broker
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "Logger Plugin: Initialized successfully using %s", config_path);

    // Register the callback to intercept published messages
    mosquitto_callback_register(plugin_id, MOSQ_EVT_ACL_CHECK, callback_acl_check, NULL, NULL);
    return MOSQ_ERR_SUCCESS;
}

/**
 * @brief Cleans up resources when the broker shuts down or unloads the plugin.
 *
 * Unregisters event callbacks, stops the message forwarder and logger, and gracefully 
 * frees allocated memory for plugin settings and WAF rules to prevent memory leaks.
 *
 * @param user_data Pointer to arbitrary user data.
 * @param opts Array of plugin options from mosquitto.conf.
 * @param opt_count Number of elements in the `opts` array.
 * @return `MOSQ_ERR_SUCCESS` upon successful cleanup.
 */
int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
    // Unregister the callback
    if (plugin_id) mosquitto_callback_unregister(plugin_id, MOSQ_EVT_ACL_CHECK, callback_acl_check, NULL);

    stop_publish_forwarder(&ext_client_pub);
    stop_subscription_forwarder(&ext_client_sub);
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