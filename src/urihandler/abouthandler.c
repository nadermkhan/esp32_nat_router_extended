#include "handler.h"
#include "cJSON.h"
 
static const char *TAG = "AboutHandler";

esp_err_t api_about_get_handler(httpd_req_t *req)
{
    ESP_LOGI(TAG, "API: About endpoint called");
    
    if (isLocked()) {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Locked");
    }

    // Check socket health first
    if (check_socket_health(req) != ESP_OK) {
        ESP_LOGW(TAG, "Socket not healthy, aborting");
        return ESP_FAIL;
    }

    cJSON *json = cJSON_CreateObject();
    if (!json) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory error");
    }

    const char *project_version = get_project_version();
    const char *project_build_date = get_project_build_date();

    cJSON_AddStringToObject(json, "version", project_version);
    cJSON_AddStringToObject(json, "hash", GLOBAL_HASH);
    cJSON_AddStringToObject(json, "buildDate", project_build_date);

    // Use chunked response for safety
    return send_json_response_chunked(req, json);
}