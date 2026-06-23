#include <stdio.h>
#include <cyaml/cyaml.h>
#include "bridge/settings.h"

#include <stdarg.h> // Required for va_list

// 1. Define a simple wrapper to route libcyaml logs to stderr
void cyaml_log_stderr(cyaml_log_t level, void *ctx, const char *fmt, va_list args) {
    vfprintf(stderr, fmt, args);
}

// 1. Define the schema for the struct fields
static const cyaml_schema_field_t settings_fields_schema[] = {
    // Map string to ext_broker_host
    CYAML_FIELD_STRING_PTR(
        "ext_broker_host", CYAML_FLAG_POINTER,
        struct settings, ext_broker_host, 0, CYAML_UNLIMITED),
    
    // Map integer to ext_broker_port
    CYAML_FIELD_INT(
        "ext_broker_port", CYAML_FLAG_DEFAULT,
        struct settings, ext_broker_port),
    
    // Map string to ext_client_id
    CYAML_FIELD_STRING_PTR(
        "ext_client_id", CYAML_FLAG_POINTER,
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

    return cfg;
}

void free_settings(struct settings* cfg) {
    if (cfg) {
        // Free the top-level struct and all nested strings in one call
        cyaml_free(&config, &settings_top_schema, cfg, 0);
    }
}