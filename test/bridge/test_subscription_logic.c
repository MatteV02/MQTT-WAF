#include <CUnit/Basic.h>
#include <string.h>
#include <mosquitto.h>
#include "bridge/subscription_logic.h"

/* Extern declarations for mock tracking variables */
extern int mock_subscribe_call_count;
extern char mock_last_subscribed_topic[256];
extern int mock_publish_copy_call_count;
extern char mock_last_published_topic[256];
extern char mock_last_published_payload[256];
extern void (*mock_ext_message_cb)(struct mosquitto *, void *, const struct mosquitto_message *);

/* Extern declaration to reset mocks */
extern void reset_mosquitto_mocks(void);

/* Dummy structures for testing (using arbitrary non-NULL pointers because the structs are opaque) */
static struct mosquitto *dummy_ext_client = (struct mosquitto *)0x1234;
static mosquitto_plugin_id_t *dummy_plugin_id = (mosquitto_plugin_id_t *)0x5678;

/* Setup function run before each test */
int init_suite(void) {
    return 0;
}

/* Teardown function run after each test */
int clean_suite(void) {
    return 0;
}

/* Test: Initialization logic */
void test_init_subscription_logic(void) {
    reset_mosquitto_mocks();
    
    int rc = init_subscription_logic(dummy_ext_client);
    
    CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
    /* Verify the callback was successfully registered into our mock */
    CU_ASSERT_PTR_NOT_NULL(mock_ext_message_cb);
}

/* Test: Forwarding a valid subscription */
void test_forward_subscription_valid(void) {
    reset_mosquitto_mocks();
    
    /* Must initialize first to set the internal g_ext_client pointer */
    init_subscription_logic(dummy_ext_client);
    
    forward_subscription(dummy_ext_client, "sensors/temperature/room1");
    
    CU_ASSERT_EQUAL(mock_subscribe_call_count, 1);
    CU_ASSERT_STRING_EQUAL(mock_last_subscribed_topic, "sensors/temperature/room1");
}

/* Test: Forwarding when the topic is NULL */
void test_forward_subscription_null_topic(void) {
    reset_mosquitto_mocks();
    init_subscription_logic(dummy_ext_client);
    
    forward_subscription(dummy_ext_client, NULL);
    
    /* Should safely do nothing */
    CU_ASSERT_EQUAL(mock_subscribe_call_count, 0);
}

/* Test: The static callback (on_ext_client_message) using our mock interceptor */
void test_on_ext_client_message(void) {
    reset_mosquitto_mocks();
    init_subscription_logic(dummy_ext_client);
    
    /* Ensure the callback was grabbed */
    CU_ASSERT_PTR_NOT_NULL_FATAL(mock_ext_message_cb);
    
    /* Construct a dummy message */
    struct mosquitto_message msg;
    memset(&msg, 0, sizeof(struct mosquitto_message));
    msg.topic = "test/forwarding";
    msg.payload = "hello broker";
    msg.payloadlen = strlen("hello broker");
    msg.qos = 1;
    msg.retain = false;
    
    /* Trigger the callback directly */
    mock_ext_message_cb(dummy_ext_client, NULL, &msg);
    
    /* Verify it parsed the message and pushed it to the broker */
    CU_ASSERT_EQUAL(mock_publish_copy_call_count, 1);
    CU_ASSERT_STRING_EQUAL(mock_last_published_topic, "test/forwarding");
    CU_ASSERT_STRING_EQUAL(mock_last_published_payload, "hello broker");
}

/* Test: Cleanup logic */
void test_cleanup_subscription_logic(void) {
    int rc = cleanup_subscription_logic(dummy_ext_client);
    CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
}

/* Main test runner */
int main(void) {
    CU_pSuite pSuite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    pSuite = CU_add_suite("Subscription Logic Test Suite", init_suite, clean_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "test_init", test_init_subscription_logic)) ||
        (NULL == CU_add_test(pSuite, "test_forward_valid", test_forward_subscription_valid)) ||
        (NULL == CU_add_test(pSuite, "test_forward_null", test_forward_subscription_null_topic)) ||
        (NULL == CU_add_test(pSuite, "test_message_callback", test_on_ext_client_message)) ||
        (NULL == CU_add_test(pSuite, "test_cleanup", test_cleanup_subscription_logic))) 
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}