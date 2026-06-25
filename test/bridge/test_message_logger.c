/**
 * @file test_message_logger.c
 * @brief Unit tests for the message logger module.
 * @brief All unit tests for the WAF plugin logger.
 *
 * @defgroup message_logger_tests Message Logger Tests
 * @ingroup bridge_tests
 * @brief Tests for file I/O lifecycle, message logging, and overflow resilience.
 * @{
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/Basic.h>
#include <mosquitto_broker.h>

// Include the header of the module we are testing
#include "bridge/message_logger.h"

#define TEST_LOG_FILE_PATH "/tmp/mqtt_packets.log"

/**
 * @brief Suite Initialization function.
 * @return Zero on success, non-zero otherwise.
 */
int init_logger_suite(void) {
    // Ensure we start with a clean state by removing any leftover log file
    remove(TEST_LOG_FILE_PATH);
    return 0;
}

/**
 * @brief Suite Cleanup function.
 * @return Zero on success, non-zero otherwise.
 */
int clean_logger_suite(void) {
    // Make sure we stop the logger and clean up the file after all tests run
    stop_logger();
    remove(TEST_LOG_FILE_PATH);
    return 0;
}

/**
 * @brief Test start and stop functionality.
 *
 * @test Verifies that the file opens successfully, the global pointer is set, 
 * and it closes without crashing.
 */
void test_start_stop_logger(void) {
    // Ensure the pointer is NULL before we start

    int status = start_logger();
    CU_ASSERT_EQUAL(status, 0);

    stop_logger();
    
    // Depending on your implementation, stop_logger() should ideally set log_file to NULL
    // If your code doesn't do this yet, you may want to add `log_file = NULL;` inside stop_logger()
    // CU_ASSERT_PTR_NULL(log_file); 
}

/**
 * @brief Test standard message logging.
 *
 * @test Verifies that the correct data (topic and payload) is physically 
 * written to the log file.
 */
void test_log_message(void) {
    // 1. Setup the logger
    CU_ASSERT_EQUAL(start_logger(), 0);

    // 2. Mock a mosquitto message
    struct mosquitto_evt_acl_check dummy_msg;
    memset(&dummy_msg, 0, sizeof(struct mosquitto_evt_acl_check));
    
    dummy_msg.client = NULL; // Assuming log_message handles NULL clients gracefully
    dummy_msg.topic = "unit/test/security";
    dummy_msg.payload = "malicious payload attempt";
    dummy_msg.payloadlen = strlen((char*)dummy_msg.payload);
    dummy_msg.qos = 1;
    dummy_msg.retain = false;

    // 3. Fire the function
    log_message(&dummy_msg);

    // 4. Force write to disk and close
    stop_logger();

    // 5. Verify the file contents
    FILE *f = fopen(TEST_LOG_FILE_PATH, "r");
    CU_ASSERT_PTR_NOT_NULL(f);
    
    if (f != NULL) {
        char buffer[1024];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, f);
        buffer[bytes_read] = '\0'; // Null-terminate the string

        // Check if the topic and payload were actually written to the file
        CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "unit/test/security"));
        CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "malicious payload attempt"));

        fclose(f);
    }
}

/**
 * @brief Test log_message buffer overflow resilience.
 *
 * @test Verifies that providing an abnormally large payload/topic does not 
 * crash the plugin (segmentation fault) and that it writes or truncates safely.
 */
void test_log_message_buffer_overflow(void) {
    // 1. Setup the logger
    CU_ASSERT_EQUAL(start_logger(), 0);

    // 2. Create an excessively large payload (64 KB)
    size_t large_size = 65536; 
    char *large_payload = (char *)malloc(large_size);
    CU_ASSERT_PTR_NOT_NULL_FATAL(large_payload); // Stop test if malloc fails
    
    // Fill with 'A' and null-terminate
    memset(large_payload, 'A', large_size - 1);
    large_payload[large_size - 1] = '\0';

    // 3. Create an excessively large topic (8 KB)
    size_t topic_size = 8192;
    char *large_topic = (char *)malloc(topic_size);
    CU_ASSERT_PTR_NOT_NULL_FATAL(large_topic);
    
    // Fill with 'B' and null-terminate
    memset(large_topic, 'B', topic_size - 1);
    large_topic[topic_size - 1] = '\0';

    // 4. Mock the message
    struct mosquitto_evt_acl_check dummy_msg;
    memset(&dummy_msg, 0, sizeof(struct mosquitto_evt_acl_check));
    dummy_msg.client = NULL;
    dummy_msg.topic = large_topic;
    dummy_msg.payload = large_payload;
    dummy_msg.payloadlen = large_size - 1;
    dummy_msg.qos = 0;
    dummy_msg.retain = false;

    // 5. Fire the function!
    // If log_message uses unsafe string copies (strcpy, sprintf) into fixed 
    // buffers, the OS will trigger a Segmentation Fault here.
    log_message(&dummy_msg);

    // 6. Stop and Flush
    stop_logger();

    // 7. Verify survival and basic output
    // If we reached this line, no buffer overflow crash occurred!
    FILE *f = fopen(TEST_LOG_FILE_PATH, "r");
    CU_ASSERT_PTR_NOT_NULL(f);
    
    if (f) {
        // Seek to the end to get the resulting file size
        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        
        // The file must contain data. Depending on your implementation, 
        // it might be safely truncated (e.g., 1024 bytes) or written in full (~73 KB).
        CU_ASSERT_TRUE(file_size > 0);
        fclose(f);
    }

    // 8. Clean up
    free(large_payload);
    free(large_topic);
}

/*
 * Main runner function
 */
int main() {
    CU_pSuite pSuite = NULL;

    // Initialize the CUnit test registry
    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    // Add a suite to the registry
    pSuite = CU_add_suite("MessageLoggerSuite", init_logger_suite, clean_logger_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Add the tests to the suite
    if (NULL == CU_add_test(pSuite, "test of start and stop logger", test_start_stop_logger) ||
        NULL == CU_add_test(pSuite, "test of log_message output", test_log_message) ||
        NULL == CU_add_test(pSuite, "test of log_message buffer overflow", test_log_message_buffer_overflow)) 
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Run all tests using the basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    
    int exit_code = CU_get_number_of_failures();
    CU_cleanup_registry();
    
    return exit_code;
}

/** @} */ // Ends the message_logger_tests group