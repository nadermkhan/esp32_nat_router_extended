#include "handler.h"
#include "cJSON.h"
 
static const char *TAG = "AboutHandler";

esp_err_t api_about_get_handler(httpd_req_t *req)
{
    ESP_LOGI(TAG, "API: Requesting about data");
    if (isLocked())
    {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Locked");
    }

    httpd_resp_set_type(req, "application/json");
    closeHeader(req);

    const char *project_version = get_project_version();
    const char *project_build_date = get_project_build_date();

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "version", project_version);
    cJSON_AddStringToObject(json, "hash", GLOBAL_HASH);
    cJSON_AddStringToObject(json, "buildDate", project_build_date);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    
    free(json_string);
    cJSON_Delete(json);
    return ret;
}