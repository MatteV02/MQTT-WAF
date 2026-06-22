#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

#include "message_logger.h"
#include "message_forwarder.h"

#define EXT_BROKER_HOST "127.0.0.1"  // Change to your external broker IP/hostname
#define EXT_BROKER_PORT 1883
#define EXT_CLIENT_ID "broker_forwarder_plugin"

static mosquitto_plugin_id_t *plugin_id = NULL;

static struct mosquitto *ext_client = NULL;

/* This callback is triggered every time a PUBLISH message flows through the broker */
int callback_message(int event, void *event_data, void *userdata) {
    struct mosquitto_evt_message *msg = event_data;
    
    log_message(msg);

    forward_message(ext_client, msg);
    
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
    
    // Open the log file. Ensure the mosquitto daemon user has write permissions here.
    int status = start_logger();
    if (status) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Cannot open /tmp/mqtt_packets.log");
        return MOSQ_ERR_UNKNOWN;
    }

    ext_client = start_forwarder(EXT_CLIENT_ID, EXT_BROKER_HOST, EXT_BROKER_PORT);
    if (!ext_client) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to init connection to external broker");
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "Logger Plugin: Initialized successfully.");

    // Register the callback to intercept published messages
    return mosquitto_callback_register(plugin_id, MOSQ_EVT_MESSAGE, callback_message, NULL, NULL);
}

/* Called when the broker is shutting down */
int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
    // Unregister the callback
    mosquitto_callback_unregister(plugin_id, MOSQ_EVT_MESSAGE, callback_message, NULL);

    stop_forwarder(ext_client);
    
    stop_logger();
    
    mosquitto_log_printf(MOSQ_LOG_INFO, "Logger Plugin: Cleaned up.");
    return MOSQ_ERR_SUCCESS;
}