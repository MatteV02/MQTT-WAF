#include <string.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

#include "message_logger.h"
#include "message_forwarder.h"
#include "settings.h" // Added our new parser header

static mosquitto_plugin_id_t *plugin_id = NULL;
static struct mosquitto *ext_client = NULL;

// Global pointer for our parsed settings
static struct settings *plugin_config = NULL;

/* This callback is triggered every time a PUBLISH message flows through the broker */
int callback_message(int event, void *event_data, void *userdata) {
    struct mosquitto_evt_message *msg = event_data;
    
    log_message(msg);

    if (ext_client) {
        forward_message(ext_client, msg);
    }
    
    // Always return SUCCESS so the broker continues processing the message
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
    
    // Look for a custom path passed from mosquitto.conf via `plugin_opt_config_path ...`
    for (int i = 0; i < opt_count; i++) {
        if (strcmp(opts[i].key, "config_path") == 0) {
            config_path = opts[i].value;
            break;
        }
    }

    // 2. Parse the settings
    plugin_config = parse_settings(config_path);
    if (!plugin_config) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to parse YAML config at %s", config_path);
        return MOSQ_ERR_UNKNOWN;
    }

    // 3. Initialize the logger
    int status = start_logger();
    if (status) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Cannot open /tmp/mqtt_packets.log");
        free_settings(plugin_config); // Prevent memory leak on abort
        plugin_config = NULL;
        return MOSQ_ERR_UNKNOWN;
    }

    // 4. Initialize the forwarder using parsed YAML settings
    ext_client = start_forwarder(
        plugin_config->ext_client_id, 
        plugin_config->ext_broker_host, 
        plugin_config->ext_broker_port
    );
    
    if (!ext_client) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to init connection to external broker");
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "Logger Plugin: Initialized successfully using %s", config_path);

    // Register the callback to intercept published messages
    return mosquitto_callback_register(plugin_id, MOSQ_EVT_MESSAGE, callback_message, NULL, NULL);
}

/* Called when the broker is shutting down */
int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
    // Unregister the callback
    mosquitto_callback_unregister(plugin_id, MOSQ_EVT_MESSAGE, callback_message, NULL);

    stop_forwarder(ext_client);
    stop_logger();
    
    // Clean up our parsed YAML settings from memory
    if (plugin_config) {
        free_settings(plugin_config);
        plugin_config = NULL;
    }
    
    mosquitto_log_printf(MOSQ_LOG_INFO, "Logger Plugin: Cleaned up.");
    return MOSQ_ERR_SUCCESS;
}