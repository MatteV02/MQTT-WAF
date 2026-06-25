/**
 * @file test_waf_rules.c
 * @brief Unit tests for the WAF rules parser and compiler.
 *
 * @defgroup waf_rules_tests Rules Parser Unit Tests
 * @brief Unit tests for the WAF rules parser and compiler.
 * @ingroup rules_tests
 *
 * @{
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "rules/waf_rules_parse.h"

/* Extern references to functions being tested */
extern struct waf_config* load_waf_rules(const char *filepath);
extern void free_waf_rules(struct waf_config *config);

/* ---------------------------------------------------------
 * TEST CASES
 * --------------------------------------------------------- */

/**
 * @brief Tests the parser's ability to successfully load a fully valid config file.
 */
void test_valid_configuration(void) {
    struct waf_config *config = load_waf_rules("test/rules/assets/test_valid.yaml");
    CU_ASSERT_PTR_NOT_NULL_FATAL(config);

    /* Verify Global config */
    CU_ASSERT_STRING_EQUAL(config->version, "1.0");

    CU_ASSERT_STRING_EQUAL(config->default_policies.publish, "allow");
    CU_ASSERT_STRING_EQUAL(config->default_policies.subscribe, "allow");

    /* Verify Message Rules */
    CU_ASSERT_EQUAL(config->rules.message_count, 1);
    CU_ASSERT_STRING_EQUAL(config->rules.message[0].id, "MSG-001");
    CU_ASSERT_TRUE(config->rules.message[0].log);
    CU_ASSERT_FALSE(config->rules.message[0].invert_match);
    CU_ASSERT_TRUE(config->rules.message[0].has_payload_regex);

    free_waf_rules(config);
}

/**
 * @brief Verifies that default values are populated correctly when missing from the YAML.
 */
void test_defaults_application(void) {
    struct waf_config *config = load_waf_rules("test/rules/assets/test_default.yaml");
    CU_ASSERT_PTR_NOT_NULL_FATAL(config);

    /* Verify Global Default Policies */
    CU_ASSERT_STRING_EQUAL(config->default_policies.publish, "allow");
    CU_ASSERT_STRING_EQUAL(config->default_policies.subscribe, "allow");

    /* Verify Message Rule Defaults */
    CU_ASSERT_TRUE_FATAL(config->rules.message_count > 0);
    CU_ASSERT_STRING_EQUAL(config->rules.message[0].action, "allow");
    CU_ASSERT_FALSE(config->rules.message[0].log);
    CU_ASSERT_FALSE(config->rules.message[0].invert_match);
    CU_ASSERT_FALSE(config->rules.message[0].has_payload_regex);
    CU_ASSERT_PTR_NULL(config->rules.message[0].payload_regex);

    /* Verify Topic Rule Defaults */
    CU_ASSERT_TRUE_FATAL(config->rules.topic_count > 0);
    CU_ASSERT_STRING_EQUAL(config->rules.topic[0].action, "allow");
    CU_ASSERT_FALSE(config->rules.topic[0].has_client_id_regex);
    CU_ASSERT_PTR_NULL(config->rules.topic[0].client_id_regex);
    
    /* Verify Topic Permissions Defaults */
    CU_ASSERT_EQUAL(config->rules.topic[0].permissions.publish_count, 0);
    CU_ASSERT_PTR_NULL(config->rules.topic[0].permissions.publish);
    CU_ASSERT_EQUAL(config->rules.topic[0].permissions.subscribe_count, 0);
    CU_ASSERT_PTR_NULL(config->rules.topic[0].permissions.subscribe);

    free_waf_rules(config);
}

/**
 * @brief Asserts that the parser properly aborts and cleans up memory if regex compilation fails.
 */
void test_invalid_regex_aborts_loading(void) {
    /* Should fail during compile_rule_regexes, clean up, and return NULL */
    struct waf_config *config = load_waf_rules("test/rules/assets/test_invalid_regex.yaml");
    CU_ASSERT_PTR_NULL(config);
}

/**
 * @brief Ensures the loading function returns NULL gracefully for missing files.
 */
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

/** @} */