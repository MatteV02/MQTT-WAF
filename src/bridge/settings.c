/**
 * @file settings.c
 * @brief Configuration settings parser for the WAF plugin bridge.
 *
 * @ingroup settings Bridge settings code unit
 */

#include <stdio.h>
#include <string.h>
#include <cyaml/cyaml.h>
#include "bridge/settings.h"

#include <stdarg.h> // Required for va_list

// Define a simple wrapper to route libcyaml logs to stderr
void cyaml_log_stderr(cyaml_log_t level, void *ctx, const char *fmt, va_list args) {
    vfprintf(stderr, fmt, args);
}

// Define the schema for the struct fields
static const cyaml_schema_field_t settings_fields_schema[] = {
    // Map string to ext_broker_host
    CYAML_FIELD_STRING_PTR(
        "ext_broker_host", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
        struct settings, ext_broker_host, 0, CYAML_UNLIMITED),
    
    // Map integer to ext_broker_port
    CYAML_FIELD_INT(
        "ext_broker_port", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL,
        struct settings, ext_broker_port),
    
    // Map string to ext_client_id
    CYAML_FIELD_STRING_PTR(
        "ext_client_id", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
        struct settings, ext_client_id, 0, CYAML_UNLIMITED),
    
    // End of schema marker
    CYAML_FIELD_END
};

// 2. Define the schema for the top-level YAML document
static const cyaml_schema_value_t settings_top_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER,
        struct settings, settings_fields_schema),
};

// 3. Setup libcyaml configuration (standard memory allocators, warning logs)
static const cyaml_config_t config = {
    .log_fn = cyaml_log_stderr,
    .mem_fn = cyaml_mem,
    .log_level = CYAML_LOG_WARNING,
};

struct settings* parse_settings(const char* filename) {
    struct settings *cfg = NULL;
    cyaml_err_t err;

    // Load, parse, allocate, and populate in one function call
    err = cyaml_load_file(filename, &config, &settings_top_schema, (cyaml_data_t **)&cfg, NULL);
    
    if (err != CYAML_OK) {
        fprintf(stderr, "libcyaml parsing error: %s\n", cyaml_strerror(err));
        return NULL;
    }

    // --- APPLY DEFAULT VALUES ---
    
    // Missing strings will be NULL
    if (cfg->ext_broker_host == NULL) {
        // Use strdup so cyaml_free() can safely deallocate it later
        cfg->ext_broker_host = strdup("localhost");
    }
    
    // Missing integers will be 0
    if (cfg->ext_broker_port == 0) {
        cfg->ext_broker_port = 1883;
    }
    
    if (cfg->ext_client_id == NULL) {
        // Use strdup here as well
        cfg->ext_client_id = strdup("default_client_id");
    }

    return cfg;
}

void free_settings(struct settings* cfg) {
    if (cfg) {
        // Free the top-level struct and all nested strings in one call
        cyaml_free(&config, &settings_top_schema, cfg, 0);
    }
}