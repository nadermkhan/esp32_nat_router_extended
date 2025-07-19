#include "handler.h"
#include "cJSON.h"

static const char *TAG_HANDLER = "StaticHandler";

void closeHeader(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "Connection", "close");
}

esp_err_t download(httpd_req_t *req, const char *fileStart)
{
    httpd_resp_set_hdr(req, "Cache-Control", "max-age=31536000");
    closeHeader(req);
    return httpd_resp_send(req, fileStart, HTTPD_RESP_USE_STRLEN);
}



esp_err_t redirectToRoot(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Temporary Redirect");
    char *currentIP = getDefaultIPByNetmask();
    char str[strlen("http://") + strlen(currentIP) + 1];
    strcpy(str, "http://");
    strcat(str, currentIP);
    httpd_resp_set_hdr(req, "Location", str);
    httpd_resp_set_hdr(req, "Connection", "Close");
    httpd_resp_send(req, "", HTTPD_RESP_USE_STRLEN);
    free(currentIP);
    return ESP_OK;
}

esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    httpd_resp_set_status(req, "302 Temporary Redirect");
    httpd_resp_set_hdr(req, "Location", "/");
    return httpd_resp_send(req, NULL, 0);
}

esp_err_t reset_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    closeHeader(req);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "message", "Device reset initiated");
    cJSON_AddBoolToObject(json, "success", true);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    
    free(json_string);
    cJSON_Delete(json);
    return ret;
}
