/**
 * @file test_evaluate_topic_rules.c
 * @brief CUnit test suite for the evaluate_topic_rules functionality.
 *
 * @defgroup evaluate_topic_rules_tests Topic Rules Evuluator Tests
 * @brief Unit tests for the message topic rules evaluation module.
 * @ingroup rules_tests
 *
 * @{
 */

#include <stdlib.h>
#include <stdbool.h>
#include <regex.h>
#include <CUnit/Basic.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

#include "rules/waf_rules_parse.h"

/** @brief External declaration of the function being tested */
extern int evaluate_topic_rules(const char *client_id, int access, const char *topic, struct topic_rule *rules, unsigned count);

/** @brief Global test rules array representing the WAF rules */
struct topic_rule test_rules[2];

/** @brief The number of test rules loaded */
unsigned test_rules_count = 2;

/* ---------------------------------------------------------
 * SUITE SETUP & TEARDOWN
 * --------------------------------------------------------- */

/**
 * @brief Initializes the test suite.
 * * Sets up Mosquitto and populates the global `test_rules` array 
 * with predefined rules (TOP-001 and TOP-002) for the test cases.
 * * @return 0 on success.
 */
int init_suite(void) {
    // Initialize mosquitto library if required for mosquitto_topic_matches_sub
    mosquitto_lib_init();

    // ---------------------------------------------------------
    // Rule 1: Restrict sensor publishing and subscribing (TOP-001)
    // ---------------------------------------------------------
    test_rules[0].id = "TOP-001";
    test_rules[0].name = "Restrict sensor publishing and subscribing";
    test_rules[0].action = "allow";
    test_rules[0].client_id_regex = "^sensor-.*";
    test_rules[0].has_client_id_regex = true;
    regcomp(&test_rules[0].compiled_client_id_regex, test_rules[0].client_id_regex, REG_EXTENDED | REG_NOSUB);
    
    test_rules[0].permissions.publish_count = 1;
    test_rules[0].permissions.publish = malloc(sizeof(char*) * 1);
    test_rules[0].permissions.publish[0] = "sensors/+/telemetry";

    test_rules[0].permissions.subscribe_count = 1;
    test_rules[0].permissions.subscribe = malloc(sizeof(char*) * 1);
    test_rules[0].permissions.subscribe[0] = "commands/broadcast/#";

    // ---------------------------------------------------------
    // Rule 2: Prevent clients from subscribing to root wildcard (TOP-002)
    // ---------------------------------------------------------
    test_rules[1].id = "TOP-002";
    test_rules[1].name = "Prevent clients from subscribing to root wildcard";
    test_rules[1].action = "drop";
    test_rules[1].client_id_regex = ".*"; // Matches any client
    test_rules[1].has_client_id_regex = true;
    regcomp(&test_rules[1].compiled_client_id_regex, test_rules[1].client_id_regex, REG_EXTENDED | REG_NOSUB);

    test_rules[1].permissions.publish_count = 0;
    test_rules[1].permissions.publish = NULL;

    test_rules[1].permissions.subscribe_count = 2;
    test_rules[1].permissions.subscribe = malloc(sizeof(char*) * 2);
    test_rules[1].permissions.subscribe[0] = "#";
    test_rules[1].permissions.subscribe[1] = "+/#";

    return 0;
}

/**
 * @brief Cleans up the test suite.
 * * Frees compiled regexes and allocated memory to prevent memory leaks 
 * during CUnit test execution.
 * * @return 0 on success.
 */
int clean_suite(void) {
    // Free compiled regexes and allocated arrays to prevent memory leaks during testing
    regfree(&test_rules[0].compiled_client_id_regex);
    free(test_rules[0].permissions.publish);
    free(test_rules[0].permissions.subscribe);

    regfree(&test_rules[1].compiled_client_id_regex);
    free(test_rules[1].permissions.subscribe);

    mosquitto_lib_cleanup();
    return 0;
}

/* ---------------------------------------------------------
 * TEST CASES
 * --------------------------------------------------------- */

/**
 * @brief Tests allowing valid publish from a sensor.
 * Expects the rule to return 1 (allow).
 */
void test_allow_valid_sensor_publish(void) {
    // Client "sensor-123" publishing to "sensors/temp/telemetry"
    // Should match TOP-001 (returns 1 for "allow")
    int result = evaluate_topic_rules("sensor-123", MOSQ_ACL_WRITE, "sensors/temp/telemetry", test_rules, test_rules_count);
    CU_ASSERT_EQUAL(result, 1);
}

/**
 * @brief Tests allowing valid subscription from a sensor.
 * Expects the rule to return 1 (allow).
 */
void test_allow_valid_sensor_subscribe(void) {
    // Client "sensor-123" subscribing to "commands/broadcast/update/v2"
    // Should match TOP-001 (returns 1 for "allow")
    int result = evaluate_topic_rules("sensor-123", MOSQ_ACL_SUBSCRIBE, "commands/broadcast/update/v2", test_rules, test_rules_count);
    CU_ASSERT_EQUAL(result, 1);
}

/**
 * @brief Tests denying sensor publish on an invalid topic.
 * Expects the rule logic to fall through and return -1.
 */
void test_deny_sensor_invalid_topic_publish(void) {
    // Client "sensor-123" publishing to "sensors/temp/data"
    // Matches Client ID, but "sensors/temp/data" DOES NOT match "sensors/+/telemetry"
    // Should fall through rules (returns -1)
    int result = evaluate_topic_rules("sensor-123", MOSQ_ACL_WRITE, "sensors/temp/data", test_rules, test_rules_count);
    CU_ASSERT_EQUAL(result, -1);
}

/**
 * @brief Tests denying an unknown client attempting a publish.
 * Expects the rule logic to fall through and return -1.
 */
void test_deny_unknown_client_publish(void) {
    // Client "unknown-device" publishing to "sensors/temp/telemetry"
    // Fails TOP-001 client ID regex. TOP-002 has no publish permissions.
    // Should fall through rules (returns -1)
    int result = evaluate_topic_rules("unknown-device", MOSQ_ACL_WRITE, "sensors/temp/telemetry", test_rules, test_rules_count);
    CU_ASSERT_EQUAL(result, -1);
}

/**
 * @brief Tests dropping a wildcard subscription from a malicious client.
 * Expects the rule to return 0 (drop).
 */
void test_drop_root_wildcard_subscription(void) {
    // Client "malicious-client" attempting to subscribe to "#"
    // Fails TOP-001 client ID regex. Matches TOP-002 client ID regex and topic.
    // Should return 0 for "drop"
    int result = evaluate_topic_rules("malicious-client", MOSQ_ACL_SUBSCRIBE, "#", test_rules, test_rules_count);
    CU_ASSERT_EQUAL(result, 0);
}

/**
 * @brief Tests dropping a root wildcard subscription from a valid sensor.
 * Expects the rule to return 0 (drop).
 */
void test_drop_sensor_root_wildcard_subscription(void) {
    // Client "sensor-123" attempting to subscribe to "+/#"
    // Matches TOP-001 client ID, but not TOP-001 subscribe topics.
    // Falls to TOP-002, matches client ID ".*" and topic "+/#"
    // Should return 0 for "drop"
    int result = evaluate_topic_rules("sensor-123", MOSQ_ACL_SUBSCRIBE, "+/#", test_rules, test_rules_count);
    CU_ASSERT_EQUAL(result, 0);
}

/**
 * @brief Tests the fallback behavior when an empty ruleset is provided.
 * Expects an immediate return of -1.
 */
void test_empty_rules_fallback(void) {
    // Pass count 0 to simulate no rules loaded
    // Should return -1 immediately
    int result = evaluate_topic_rules("sensor-123", MOSQ_ACL_WRITE, "sensors/temp/telemetry", test_rules, 0);
    CU_ASSERT_EQUAL(result, -1);
}

/**
 * @brief Tests a rule applying to everyone if the client regex is missing.
 * Expects a rule with `has_client_id_regex == false` to evaluate the topic match.
 */
void test_missing_client_regex_applies_to_all(void) {
    // Create a rule with NO regex (has_client_id_regex = false)
    struct topic_rule no_regex_rule;
    memset(&no_regex_rule, 0, sizeof(struct topic_rule));
    no_regex_rule.action = "drop";
    no_regex_rule.has_client_id_regex = false; // Simulate missing regex in YAML
    
    no_regex_rule.permissions.publish_count = 1;
    no_regex_rule.permissions.publish = malloc(sizeof(char*));
    no_regex_rule.permissions.publish[0] = "banned/topic";

    // Expected: It should drop the message because it applies to EVERYONE.
    int result = evaluate_topic_rules("any-client", MOSQ_ACL_WRITE, "banned/topic", &no_regex_rule, 1);
    
    // If your code has the bug, this assert will fail (it will return -1 instead of 0)
    CU_ASSERT_EQUAL(result, 0); 
    
    free(no_regex_rule.permissions.publish);
}

/**
 * @brief Tests fallback closure if a rule action contains a typo.
 * Expects an unrecognized action to safely fail closed and return 0.
 */
void test_unrecognized_action_fails_closed(void) {
    struct topic_rule typo_rule = test_rules[0];
    typo_rule.action = "Allow"; // Capitalized typo!
    
    int result = evaluate_topic_rules("sensor-123", MOSQ_ACL_WRITE, "sensors/temp/telemetry", &typo_rule, 1);
    
    // Expected: If action is invalid, fail closed (drop = 0)
    // If your code has the bug, it falls through and returns -1
    CU_ASSERT_EQUAL(result, 0);
}

/* ---------------------------------------------------------
 * MAIN ROUTINE
 * --------------------------------------------------------- */

int main() {
    CU_pSuite pSuite = NULL;

    // Initialize CUnit test registry
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    // Add suite to registry
    pSuite = CU_add_suite("Topic_Rules_Suite", init_suite, clean_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Add tests to suite
    if ((NULL == CU_add_test(pSuite, "test_allow_valid_sensor_publish", test_allow_valid_sensor_publish)) ||
        (NULL == CU_add_test(pSuite, "test_allow_valid_sensor_subscribe", test_allow_valid_sensor_subscribe)) ||
        (NULL == CU_add_test(pSuite, "test_deny_sensor_invalid_topic_publish", test_deny_sensor_invalid_topic_publish)) ||
        (NULL == CU_add_test(pSuite, "test_deny_unknown_client_publish", test_deny_unknown_client_publish)) ||
        (NULL == CU_add_test(pSuite, "test_drop_root_wildcard_subscription", test_drop_root_wildcard_subscription)) ||
        (NULL == CU_add_test(pSuite, "test_drop_sensor_root_wildcard_subscription", test_drop_sensor_root_wildcard_subscription)) ||
        (NULL == CU_add_test(pSuite, "test_empty_rules_fallback", test_empty_rules_fallback))) 
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Run tests using basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    
    return CU_get_error();
}

/** @} */