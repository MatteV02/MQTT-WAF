/**
 * @file test_settings.c
 * @brief Unit tests for the bridge settings configuration parser.
 *
 * This file contains CUnit test cases to verify the behavior of the YAML 
 * parsing logic defined in settings.h. It tests successful parsing, default 
 * value application, and error handling for missing or malformed files.
 *
 * @defgroup settings_tests Settings Unit Tests
 * @brief Unit tests for bridge settings
 * @ingroup bridge_tests
 *
 * @{
 */

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "bridge/settings.h"

// --- File names for testing ---
const char* VALID_YAML_FILE = "test/bridge/assets/test_valid_config.yaml";
const char* INVALID_YAML_FILE = "test/bridge/assets/test_invalid_config.yaml";
const char* MISSING_YAML_FILE = "does_not_exist.yaml";
// ADDED: A file that contains valid YAML, but is missing the target fields (e.g., just "{}")
const char* EMPTY_YAML_FILE = "test/bridge/assets/test_empty_config.yaml";

// --- Suite Setup and Teardown ---

/* * The suite initialization function.
 * Creates temporary YAML files required for testing.
 * Returns zero on success, non-zero otherwise.
 */
int init_suite_settings(void) {
    return 0;
}

/* * The suite cleanup function.
 * Deletes the temporary YAML files.
 * Returns zero on success, non-zero otherwise.
 */
int clean_suite_settings(void) {
    return 0;
}

// --- Test Cases ---

/* Test parsing a valid YAML file */
void test_parse_settings_valid(void) {
    struct settings* cfg = parse_settings(VALID_YAML_FILE);
    
    // Assert struct was allocated
    CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);
    
    // Assert fields are populated correctly
    CU_ASSERT_STRING_EQUAL(cfg->ext_broker_host, "localhost");
    CU_ASSERT_EQUAL(cfg->ext_broker_port, 1883);
    CU_ASSERT_STRING_EQUAL(cfg->ext_client_id, "test_client_123");
    
    // Clean up
    free_settings(cfg);
}

/* ADDED: Test parsing a YAML file missing fields to ensure defaults are applied */
void test_parse_settings_defaults(void) {
    struct settings* cfg = parse_settings(EMPTY_YAML_FILE);
    
    // Assert struct was allocated successfully
    CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);
    
    // Assert fields are populated with our post-processed default values
    CU_ASSERT_STRING_EQUAL(cfg->ext_broker_host, "localhost");
    CU_ASSERT_EQUAL(cfg->ext_broker_port, 1883);
    CU_ASSERT_STRING_EQUAL(cfg->ext_client_id, "default_client_id");
    
    // Clean up
    free_settings(cfg);
}

/* Test behavior when the file does not exist */
void test_parse_settings_missing_file(void) {
    struct settings* cfg = parse_settings(MISSING_YAML_FILE);
    
    // Assuming implementation returns NULL when file is not found
    CU_ASSERT_PTR_NULL(cfg);
}

/* Test behavior when passing a NULL filename pointer */
void test_parse_settings_null_filename(void) {
    struct settings* cfg = parse_settings(NULL);
    
    // Implementation should handle NULL pointers gracefully
    CU_ASSERT_PTR_NULL(cfg);
}

/* Test behavior when parsing a malformed YAML file */
void test_parse_settings_invalid_yaml(void) {
    struct settings* cfg = parse_settings(INVALID_YAML_FILE);
    
    // Assuming implementation returns NULL on parse error
    CU_ASSERT_PTR_NULL(cfg); 
    
    if (cfg != NULL) {
        free_settings(cfg);
    }
}

/* Test that free_settings handles a NULL pointer without crashing */
void test_free_settings_null(void) {
    // If free_settings is written safely, this will not segfault
    free_settings(NULL);
    CU_PASS("Successfully handled NULL in free_settings");
}

// --- Main Runner ---

int main() {
    CU_pSuite pSuite = NULL;

    // Initialize the CUnit test registry
    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    // Add a suite to the registry
    pSuite = CU_add_suite("Suite_Settings", init_suite_settings, clean_suite_settings);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Add the tests to the suite
    if ((NULL == CU_add_test(pSuite, "test of parse_settings() with valid file", test_parse_settings_valid)) ||
        (NULL == CU_add_test(pSuite, "test of parse_settings() defaults applied", test_parse_settings_defaults)) || // <--- ADDED HERE
        (NULL == CU_add_test(pSuite, "test of parse_settings() with missing file", test_parse_settings_missing_file)) ||
        (NULL == CU_add_test(pSuite, "test of parse_settings() with NULL filename", test_parse_settings_null_filename)) ||
        (NULL == CU_add_test(pSuite, "test of parse_settings() with invalid yaml", test_parse_settings_invalid_yaml)) ||
        (NULL == CU_add_test(pSuite, "test of free_settings() with NULL pointer", test_free_settings_null))) 
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Run all tests using the basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    
    // Clean up registry and return
    CU_cleanup_registry();
    return CU_get_error();
}

/** @} */