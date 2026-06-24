#include <CUnit/Basic.h>

#include "rules/waf_rules_parse.h"

/* Extern references to functions being tested */
extern struct waf_config* load_waf_rules(const char *filepath);
extern void free_waf_rules(struct waf_config *config);

/* ---------------------------------------------------------
 * TEST CASES
 * --------------------------------------------------------- */

void test_valid_configuration(void) {
    struct waf_config *config = load_waf_rules("test/rules/assets/test_valid.yaml");
    CU_ASSERT_PTR_NOT_NULL_FATAL(config);

    /* Verify Global config */
    CU_ASSERT_STRING_EQUAL(config->version, "1.0");
    CU_ASSERT_STRING_EQUAL(config->default_policies.connection, "deny");

    /* Verify Connection Rules */
    CU_ASSERT_EQUAL(config->rules.connection_count, 1);
    CU_ASSERT_STRING_EQUAL(config->rules.connection[0].id, "CONN-001");
    CU_ASSERT_STRING_EQUAL(config->rules.connection[0].action, "deny");
    CU_ASSERT_TRUE(config->rules.connection[0].require_tls);
    CU_ASSERT_EQUAL(config->rules.connection[0].ip_list_count, 2);
    CU_ASSERT_STRING_EQUAL(config->rules.connection[0].ip_list[0], "10.0.0.1");

    /* Verify Regex compiled successfully */
    CU_ASSERT_TRUE(config->rules.connection[0].has_client_id_regex);

    /* Verify Message Rules */
    CU_ASSERT_EQUAL(config->rules.message_count, 1);
    CU_ASSERT_STRING_EQUAL(config->rules.message[0].id, "MSG-001");
    CU_ASSERT_TRUE(config->rules.message[0].log);
    CU_ASSERT_FALSE(config->rules.message[0].invert_match);
    CU_ASSERT_TRUE(config->rules.message[0].has_payload_regex);

    free_waf_rules(config);
}

void test_defaults_application(void) {
    struct waf_config *config = load_waf_rules("test/rules/assets/test_default.yaml");
    CU_ASSERT_PTR_NOT_NULL_FATAL(config);

    /* Test Authentication Rule Defaults */
    CU_ASSERT_EQUAL(config->rules.authentication_count, 1);
    struct authentication_rule *auth_rule = &config->rules.authentication[0];
    
    CU_ASSERT_STRING_EQUAL(auth_rule->action, "allow");
    CU_ASSERT_EQUAL(auth_rule->trigger.max_failed_attempts, 5); // Defaulted
    CU_ASSERT_STRING_EQUAL(auth_rule->trigger.time_window, "60s"); // Defaulted
    CU_ASSERT_STRING_EQUAL(auth_rule->enforcement.lockout_duration, "5m"); // Defaulted
    CU_ASSERT_STRING_EQUAL(auth_rule->enforcement.target, "ip"); // Defaulted

    /* Test Rate Limiting Defaults */
    CU_ASSERT_EQUAL(config->rules.rate_limiting_count, 1);
    struct rate_limiting_rule *rl_rule = &config->rules.rate_limiting[0];
    
    CU_ASSERT_STRING_EQUAL(rl_rule->action, "allow");
    CU_ASSERT_EQUAL(rl_rule->quota.max_messages, 100); // Defaulted
    CU_ASSERT_STRING_EQUAL(rl_rule->quota.time_window, "1s"); // Defaulted

    free_waf_rules(config);
}

void test_invalid_regex_aborts_loading(void) {
    /* Should fail during compile_rule_regexes, clean up, and return NULL */
    struct waf_config *config = load_waf_rules("test/rules/assets/test_invalid_regex.yaml");
    CU_ASSERT_PTR_NULL(config);
}

void test_file_not_found(void) {
    /* Should fail gracefully on cyaml_load_file and return NULL */
    struct waf_config *config = load_waf_rules("non_existent_file_12345.yaml");
    CU_ASSERT_PTR_NULL(config);
}


/* ---------------------------------------------------------
 * TEST SUITE SETUP & MAIN
 * --------------------------------------------------------- */

int init_suite(void) { return 0; }
int clean_suite(void) { return 0; }

int main() {
    CU_pSuite pSuite = NULL;

    /* Initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    /* Add a suite to the registry */
    pSuite = CU_add_suite("WAF_Rules_Parser_Suite", init_suite, clean_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "test_valid_configuration", test_valid_configuration)) ||
        (NULL == CU_add_test(pSuite, "test_defaults_application", test_defaults_application)) ||
        (NULL == CU_add_test(pSuite, "test_invalid_regex_aborts_loading", test_invalid_regex_aborts_loading)) ||
        (NULL == CU_add_test(pSuite, "test_file_not_found", test_file_not_found))) 
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Run all tests using the basic interface */
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    
    int failures = CU_get_number_of_failures();
    CU_cleanup_registry();
    
    return failures;
}