/**
 * @file test_message_forwarder.c
 * @brief Unit tests for the message forwarder module.
 * @brief All unit tests for the WAF plugin.
 * * * @defgroup message_forwarder_tests Message Forwarder Tests
 * @ingroup tests
 * @brief Tests for start/stop lifecycle and message filtering.
 * @{
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include <CUnit/Basic.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>

// Include the header of the module we are testing
#include "bridge/message_forwarder.h"

/*
 * Suite Initialization/Cleanup functions.
 */
int init_forwarder_suite(void) { return 0; }
int clean_forwarder_suite(void) { return 0; }

/**
 * @brief Test start and stop functionality.
 * * @test Verifies that the external client object is created, the background 
 * thread starts, and it shuts down cleanly without hanging.
 */
void test_start_stop_forwarder(void) {
    // Attempt an async connection to localhost
    struct mosquitto *ext_client = start_forwarder("test_forwarder", "localhost", 1883);
    
    // Ensure the client object was instantiated
    CU_ASSERT_PTR_NOT_NULL(ext_client);
    
    // Cleanly stop the background thread and destroy the client
    stop_forwarder(ext_client);

    CU_PASS("Message forwarder started and stopped successfully.");
}

/**
 * @brief Test forwarding a valid standard message.
 * * @test Verifies that a normal message passes the internal checks and is 
 * queued for publishing.
 */
void test_forward_message_valid(void) {
    struct mosquitto *ext_client = start_forwarder("test_forwarder", "localhost", 1883);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ext_client);

    // Mock a valid message
    struct mosquitto_evt_acl_check dummy_msg;
    memset(&dummy_msg, 0, sizeof(struct mosquitto_evt_acl_check));
    dummy_msg.topic = "sensor/temperature";
    dummy_msg.payload = "22.5";
    dummy_msg.payloadlen = strlen((char*)dummy_msg.payload);
    dummy_msg.qos = 0;
    dummy_msg.retain = false;

    // Because we are using the async client, mosquitto_publish will return 
    // MOSQ_ERR_SUCCESS (0) simply for successfully enqueueing the message.
    int rc = publish_forward(ext_client, &dummy_msg);
    CU_ASSERT_EQUAL(rc, 0);

    stop_forwarder(ext_client);
}

/**
 * @brief Test forwarding a valid standard message.
 * * @test Verifies that a normal message passes the internal checks and is 
 * queued for publishing.
 */
void test_forward_message_sys_topic(void) {
    struct mosquitto *ext_client = start_forwarder("test_forwarder", "localhost", 1883);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ext_client);

    // Mock a $SYS message
    struct mosquitto_evt_acl_check dummy_msg;
    memset(&dummy_msg, 0, sizeof(struct mosquitto_evt_acl_check));
    dummy_msg.topic = "$SYS/broker/uptime";
    dummy_msg.payload = "12345";
    dummy_msg.payloadlen = strlen((char*)dummy_msg.payload);
    dummy_msg.qos = 0;
    dummy_msg.retain = false;

    // Your code returns 0 when ignoring a $SYS topic
    int rc = publish_forward(ext_client, &dummy_msg);
    CU_ASSERT_EQUAL(rc, 0);

    stop_forwarder(ext_client);
}

/**
 * @brief Test handling of NULL pointers.
 * * @test Verifies that the plugin doesn't segfault if given null pointers.
 */
void test_forward_message_nulls(void) {
    struct mosquitto *ext_client = start_forwarder("test_forwarder", "localhost", 1883);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ext_client);

    struct mosquitto_evt_acl_check dummy_msg;
    memset(&dummy_msg, 0, sizeof(struct mosquitto_evt_acl_check));
    dummy_msg.topic = NULL; // Intentionally missing topic

    // Test missing client
    CU_ASSERT_EQUAL(publish_forward(NULL, &dummy_msg), -1);
    
    // Test missing message
    CU_ASSERT_EQUAL(publish_forward(ext_client, NULL), -1);
    
    // Test missing topic within message
    CU_ASSERT_EQUAL(publish_forward(ext_client, &dummy_msg), -1);

    stop_forwarder(ext_client);
}

/*
 * Main runner function
 */
int main() {
    CU_pSuite pSuite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    pSuite = CU_add_suite("MessageForwarderSuite", init_forwarder_suite, clean_forwarder_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Register all four tests
    if (NULL == CU_add_test(pSuite, "test of start and stop forwarder", test_start_stop_forwarder) ||
        NULL == CU_add_test(pSuite, "test of valid message forwarding", test_forward_message_valid) ||
        NULL == CU_add_test(pSuite, "test of $SYS topic ignore logic", test_forward_message_sys_topic) ||
        NULL == CU_add_test(pSuite, "test of NULL pointer handling", test_forward_message_nulls)) 
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    
    int exit_code = CU_get_number_of_failures();
    CU_cleanup_registry();
    
    return exit_code;
}

/** @} */ // Ends the message_forwarder_tests group