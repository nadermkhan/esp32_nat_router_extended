#ifndef HANDLER_H
#define HANDLER_H

#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "router_globals.h"
#include "helper.h"
#include "cJSON.h"

// Security constants
#define MAX_REQUEST_SIZE 4096
#define MAX_PARAM_LENGTH 256
#define API_RATE_LIMIT_WINDOW 60000  // 1 minute in ms
#define API_RATE_LIMIT_MAX_REQUESTS 100

// API Response helpers
typedef struct {
    bool success;
    char *message;
    cJSON *data;
    int status_code;
} api_response_t;

// Rate limiting structure
typedef struct {
    uint32_t request_count;
    int64_t window_start;
    char client_ip[16];
} rate_limit_entry_t;

// Function declarations
esp_err_t send_api_response(httpd_req_t *req, api_response_t *response);
bool check_rate_limit(httpd_req_t *req);
bool validate_request_size(httpd_req_t *req);
void sanitize_string_input(char *input, size_t max_len);
bool is_valid_ip_address(const char *ip);
bool is_valid_port(int port);

// API Handlers
esp_err_t api_about_get_handler(httpd_req_t *req);
esp_err_t api_config_get_handler(httpd_req_t *req);
esp_err_t api_config_post_handler(httpd_req_t *req);
esp_err_t api_advanced_get_handler(httpd_req_t *req);
esp_err_t api_advanced_post_handler(httpd_req_t *req);
esp_err_t api_clients_get_handler(httpd_req_t *req);
esp_err_t api_clients_block_post_handler(httpd_req_t *req);
esp_err_t api_clients_unblock_post_handler(httpd_req_t *req);
esp_err_t api_portmap_get_handler(httpd_req_t *req);
esp_err_t api_portmap_post_handler(httpd_req_t *req);
esp_err_t api_scan_start_post_handler(httpd_req_t *req);
esp_err_t api_scan_result_get_handler(httpd_req_t *req);
esp_err_t api_system_get_handler(httpd_req_t *req);
esp_err_t api_system_restart_post_handler(httpd_req_t *req);
esp_err_t api_apply_post_handler(httpd_req_t *req);
esp_err_t api_lock_get_handler(httpd_req_t *req);
esp_err_t api_lock_post_handler(httpd_req_t *req);
esp_err_t api_unlock_post_handler(httpd_req_t *req);

// Lock functions
bool isLocked(void);
void lockUI(void);

#endif