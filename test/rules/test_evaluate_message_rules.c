#include <string.h>
#include <stdbool.h>
#include <CUnit/Basic.h>
#include <regex.h>
#include <mosquitto.h>

// Include your header file here
#include "rules/waf_rules_parse.h"

// Forward declaration of the function we are testing
int evaluate_message_rules(const char *topic, const void *payload, int payloadlen, struct message_rule *rules, unsigned count);

/* ---------------------------------------------------------
 * TEST CASES
 * --------------------------------------------------------- */

void test_sql_injection_drop(void) {
    struct message_rule rule;
    memset(&rule, 0, sizeof(rule));
    
    rule.id = "MSG-001";
    rule.action = "drop";
    char *topics[] = {"#"};
    rule.topics = topics;
    rule.topics_count = 1;
    rule.has_payload_regex = true;
    rule.log = false;
    rule.invert_match = false;
    
    regcomp(&rule.compiled_payload_regex, "(UNION.*SELECT|DROP.*TABLE)", REG_EXTENDED | REG_ICASE);

    // Test 1: Malicious payload -> Should return 0 (Drop)
    const char *bad_payload = "123 UNION SELECT password FROM users";
    int res = evaluate_message_rules("sensors/data", bad_payload, strlen(bad_payload), &rule, 1);
    CU_ASSERT_EQUAL(res, 0);

    // Test 2: Benign payload -> Rule bypasses, Should return -1 (Fallback)
    const char *good_payload = "123 NORMAL DATA";
    res = evaluate_message_rules("sensors/data", good_payload, strlen(good_payload), &rule, 1);
    CU_ASSERT_EQUAL(res, -1);

    regfree(&rule.compiled_payload_regex);
}

void test_strict_json_invert_match(void) {
    struct message_rule rule;
    memset(&rule, 0, sizeof(rule));
    
    rule.id = "MSG-002";
    rule.action = "drop";
    char *topics[] = {"sensors/+/data"};
    rule.topics = topics;
    rule.topics_count = 1;
    rule.has_payload_regex = true;
    rule.invert_match = true; // Drop if DOES NOT match regex
    
    regcomp(&rule.compiled_payload_regex, "^\\{.*\\}$", REG_EXTENDED | REG_NOSUB);

    // Test 1: Valid JSON payload -> regex matches -> inverted to false -> rule bypassed -> returns -1
    const char *valid_payload = "{\"temperature\": 22.5}";
    int res = evaluate_message_rules("sensors/livingroom/data", valid_payload, strlen(valid_payload), &rule, 1);
    CU_ASSERT_EQUAL(res, -1);

    // Test 2: Invalid JSON payload -> regex fails -> inverted to true -> triggers drop -> returns 0
    const char *invalid_payload = "temperature=22.5";
    res = evaluate_message_rules("sensors/livingroom/data", invalid_payload, strlen(invalid_payload), &rule, 1);
    CU_ASSERT_EQUAL(res, 0);

    // Test 3: Topic mismatch -> rule completely bypassed despite invalid payload -> returns -1
    res = evaluate_message_rules("other/topic", invalid_payload, strlen(invalid_payload), &rule, 1);
    CU_ASSERT_EQUAL(res, -1);

    regfree(&rule.compiled_payload_regex);
}

void test_raw_buffer_safety(void) {
    struct message_rule rule;
    memset(&rule, 0, sizeof(rule));
    
    rule.id = "MSG-003";
    rule.action = "drop";
    char *topics[] = {"#"};
    rule.topics = topics;
    rule.topics_count = 1;
    rule.has_payload_regex = true;
    
    // Look for string "BAD"
    regcomp(&rule.compiled_payload_regex, "BAD", REG_EXTENDED);

    // Create a raw byte buffer WITHOUT a null terminator
    char raw_payload[5] = {'B', 'A', 'D', 0xFF, 0x00}; 
    // Notice we pass length 3. If the evaluator doesn't isolate the length properly, 
    // regexec might over-read into undefined behavior.
    
    int res = evaluate_message_rules("test", raw_payload, 3, &rule, 1);
    CU_ASSERT_EQUAL(res, 0); // Should catch the "BAD" part cleanly

    regfree(&rule.compiled_payload_regex);
}

void test_empty_payload_handling(void) {
    struct message_rule rule;
    memset(&rule, 0, sizeof(rule));
    
    rule.id = "MSG-004";
    rule.action = "drop";
    char *topics[] = {"#"};
    rule.topics = topics;
    rule.topics_count = 1;
    rule.has_payload_regex = true;
    rule.invert_match = true; // Demands that a regex match occurs, otherwise drops
    
    regcomp(&rule.compiled_payload_regex, "^.+$", REG_EXTENDED); // Demands at least 1 character

    // MQTT allows 0-byte payloads (payloadlen = 0, payload = NULL)
    int res = evaluate_message_rules("test", NULL, 0, &rule, 1);
    
    // Empty payload fails the regex match -> inverted to true -> triggers drop (0)
    CU_ASSERT_EQUAL(res, 0); 

    regfree(&rule.compiled_payload_regex);
}


/* ---------------------------------------------------------
 * TEST SUITE SETUP & MAIN
 * --------------------------------------------------------- */

int init_suite(void) { 
    mosquitto_lib_init(); // Initialize libmosquitto for mosquitto_topic_matches_sub
    return 0; 
}

int clean_suite(void) { 
    mosquitto_lib_cleanup();
    return 0; 
}

int main(void) {
    CU_pSuite pSuite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    pSuite = CU_add_suite("WAF_Message_Rules_Suite", init_suite, clean_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (
        (NULL == CU_add_test(pSuite, "Test SQL Injection Drop", test_sql_injection_drop)) ||
        (NULL == CU_add_test(pSuite, "Test Strict JSON & Invert Match", test_strict_json_invert_match)) ||
        (NULL == CU_add_test(pSuite, "Test Raw Buffer Safety (No Null Terminator)", test_raw_buffer_safety)) ||
        (NULL == CU_add_test(pSuite, "Test Empty Payload Handling", test_empty_payload_handling))
    ) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}