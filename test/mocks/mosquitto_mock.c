#include <stdio.h>
#include <stdarg.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

/* Corrected implementation for broker logging (returns void) */
void mosquitto_log_printf(int level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[MOCK BROKER LOG - Level %d] ", level);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

/* Dummy implementation to return a fake client ID */
const char *mosquitto_client_id(const struct mosquitto *mosq) {
    // Handle NULL gracefuly for tests
    if (!mosq) return "null_mock_client";
    return "mock_test_client_id";
}

/* Corrected callback register (uses MOSQ_FUNC_generic_callback) */
int mosquitto_callback_register(
    mosquitto_plugin_id_t *identifier, 
    int event, 
    MOSQ_FUNC_generic_callback cb_func, 
    const void *event_data, 
    void *userdata) 
{
    return MOSQ_ERR_SUCCESS;
}

/* Corrected callback unregister (uses MOSQ_FUNC_generic_callback) */
int mosquitto_callback_unregister(
    mosquitto_plugin_id_t *identifier, 
    int event, 
    MOSQ_FUNC_generic_callback cb_func, 
    const void *event_data) 
{
    return MOSQ_ERR_SUCCESS;
}

/* Corrected broker publish copy (payload is const void *) */
int mosquitto_broker_publish_copy(
    const char *clientid, 
    const char *topic, 
    int payloadlen, 
    const void *payload, 
    int qos, 
    bool retain, 
    mosquitto_property *properties) 
{
    return MOSQ_ERR_SUCCESS;
}