#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

/* --- MOCK STATE VARIABLES (Exposed to tests) --- */
int mock_subscribe_call_count = 0;
char mock_last_subscribed_topic[256] = {0};

int mock_publish_copy_call_count = 0;
char mock_last_published_topic[256] = {0};
int mock_last_published_payloadlen = 0;
char mock_last_published_payload[256] = {0};

void (*mock_ext_message_cb)(struct mosquitto *, void *, const struct mosquitto_message *) = NULL;

/* Helper to reset mock state before each test */
void reset_mosquitto_mocks(void) {
    mock_subscribe_call_count = 0;
    memset(mock_last_subscribed_topic, 0, sizeof(mock_last_subscribed_topic));
    
    mock_publish_copy_call_count = 0;
    memset(mock_last_published_topic, 0, sizeof(mock_last_published_topic));
    mock_last_published_payloadlen = 0;
    memset(mock_last_published_payload, 0, sizeof(mock_last_published_payload));
    
    mock_ext_message_cb = NULL;
}

/* --- MOCKED MOSQUITTO FUNCTIONS --- */

void mosquitto_log_printf(int level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[MOCK LOG - Lvl %d] ", level);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

const char *mosquitto_client_id(const struct mosquitto *mosq) {
    if (!mosq) return "null_mock_client";
    return "mock_test_client_id";
}

int mosquitto_callback_register(mosquitto_plugin_id_t *identifier, int event, MOSQ_FUNC_generic_callback cb_func, const void *event_data, void *userdata) {
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_callback_unregister(mosquitto_plugin_id_t *identifier, int event, MOSQ_FUNC_generic_callback cb_func, const void *event_data) {
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_broker_publish_copy(const char *clientid, const char *topic, int payloadlen, const void *payload, int qos, bool retain, mosquitto_property *properties) {
    mock_publish_copy_call_count++;
    if (topic) {
        strncpy(mock_last_published_topic, topic, sizeof(mock_last_published_topic) - 1);
    }
    if (payload && payloadlen > 0) {
        mock_last_published_payloadlen = payloadlen;
        memcpy(mock_last_published_payload, payload, payloadlen < 256 ? payloadlen : 255);
    }
    return MOSQ_ERR_SUCCESS;
}

/* Intercept the message callback registration so we can trigger it in tests */
void mosquitto_message_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *)) {
    mock_ext_message_cb = on_message;
}

/* Intercept subscriptions to verify topics */
int mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos) {
    mock_subscribe_call_count++;
    if (sub) {
        strncpy(mock_last_subscribed_topic, sub, sizeof(mock_last_subscribed_topic) - 1);
    }
    return MOSQ_ERR_SUCCESS;
}