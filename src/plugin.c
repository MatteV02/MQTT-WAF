#include <stdio.h>
#include <string.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

#include "message_logger.h"

#define EXT_BROKER_HOST "127.0.0.1"  // Change to your external broker IP/hostname
#define EXT_BROKER_PORT 1883
#define EXT_CLIENT_ID "broker_forwarder_plugin"

static mosquitto_plugin_id_t *plugin_id = NULL;

static struct mosquitto *ext_client = NULL;

/* This callback is triggered every time a PUBLISH message flows through the broker */
int callback_message(int event, void *event_data, void *userdata) {
    struct mosquitto_evt_message *msg = event_data;
    
    log_message(msg);

    if (ext_client && msg && msg->topic) {
        
        // Optional: Ignore internal $SYS topics to prevent spamming the external broker
        if (strncmp(msg->topic, "$SYS", 4) == 0) {
            return MOSQ_ERR_SUCCESS;
        }

        // Publish the payload to the external broker
        // mosquitto_publish is thread-safe and non-blocking when used with mosquitto_loop_start()
        int rc = mosquitto_publish(ext_client, 
                                   NULL,            // message id (not needed)
                                   msg->topic,      // same topic
                                   msg->payloadlen, // same length
                                   msg->payload,    // same payload
                                   msg->qos,        // same QoS
                                   msg->retain);    // same retain flag
                                   
        if (rc != MOSQ_ERR_SUCCESS) {
            mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to forward msg on %s (Error: %d)", msg->topic, rc);
        }
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
    
    // Open the log file. Ensure the mosquitto daemon user has write permissions here.
    log_file = fopen("/tmp/mqtt_packets.log", "a");
    if (!log_file) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Cannot open /tmp/mqtt_packets.log");
        return MOSQ_ERR_UNKNOWN;
    }

    mosquitto_lib_init();
    
    ext_client = mosquitto_new(EXT_CLIENT_ID, true, NULL);
    if (!ext_client) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to create external MQTT client");
        fclose(log_file);
        return MOSQ_ERR_UNKNOWN;
    }

    int rc = mosquitto_connect_async(ext_client, EXT_BROKER_HOST, EXT_BROKER_PORT, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to init connection to external broker");
        // We log the error but don't fail the plugin init, allowing local logging to continue
    } else {
        // mosquitto_loop_start creates a background thread to handle network I/O
        mosquitto_loop_start(ext_client);
        mosquitto_log_printf(MOSQ_LOG_INFO, "Logger Plugin: Forwarder started (%s:%d)", EXT_BROKER_HOST, EXT_BROKER_PORT);
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "Logger Plugin: Initialized successfully.");

    // Register the callback to intercept published messages
    return mosquitto_callback_register(plugin_id, MOSQ_EVT_MESSAGE, callback_message, NULL, NULL);
}

/* Called when the broker is shutting down */
int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
    // Unregister the callback
    mosquitto_callback_unregister(plugin_id, MOSQ_EVT_MESSAGE, callback_message, NULL);

    if (ext_client) {
        mosquitto_disconnect(ext_client);
        mosquitto_loop_stop(ext_client, true); // wait for the network thread to finish gracefully
        mosquitto_destroy(ext_client);
        ext_client = NULL;
    }
    mosquitto_lib_cleanup();
    
    // Safely close the file handle
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    
    mosquitto_log_printf(MOSQ_LOG_INFO, "Logger Plugin: Cleaned up.");
    return MOSQ_ERR_SUCCESS;
}