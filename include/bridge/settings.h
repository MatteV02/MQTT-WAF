/**
 * @file settings.h
 * @brief Configuration settings parser for the WAF plugin bridge.
 *
 * This header defines the configuration data structure and the functions 
 * required to parse the external broker settings from a YAML file using libcyaml.
 *
 * @defgroup settings Settings
 * @brief Configuration settings parser for the WAF plugin bridge.
 * @ingroup bridge
 *
 * @{
 */

#ifndef SETTINGS_H_
#define SETTINGS_H_

/**
 * @brief Holds the configuration settings for the external MQTT broker connection.
 *
 * This structure stores the parsed values from the YAML settings file.
 * Memory for the strings is dynamically allocated during parsing and must 
 * be freed using free_settings().
 */
struct settings {
    /** 
     * @brief The hostname or IP address of the external broker.
     * @note Defaults to "localhost" if omitted from the configuration. 
     */
    char* ext_broker_host;

    /** 
     * @brief The port number of the external broker.
     * @note Defaults to 1883 if omitted from the configuration. 
     */
    int ext_broker_port;

    /** 
     * @brief The client ID used to connect to the external broker.
     * @note Defaults to "default_client_id" if omitted from the configuration. 
     */
    char* ext_client_id;
};

/**
 * @brief Parses a YAML configuration file and populates the settings structure.
 *
 * This function reads the specified YAML file, allocates memory for the 
 * settings structure, and populates its fields. If any optional fields are 
 * missing from the YAML file, the function applies standard default values.
 *
 * @param filename The file path to the YAML configuration file to be parsed.
 * Passing NULL will gracefully return NULL.
 * @return A pointer to a newly allocated `settings` structure on success, 
 * or `NULL` if the file does not exist, or if a parsing error occurs.
 */
struct settings* parse_settings(const char* filename);

/**
 * @brief Frees the dynamically allocated settings structure.
 *
 * This function safely deallocates the top-level `settings` struct as well 
 * as any dynamically allocated strings nested within it. 
 * * @note This function safely handles `NULL` pointers; passing `NULL` results in a no-op.
 *
 * @param cfg A pointer to the `settings` structure to be freed.
 */
void free_settings(struct settings* cfg);

#endif // SETTINGS_H_

/** @} */