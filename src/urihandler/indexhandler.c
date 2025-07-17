#include "handler.h"
#include <sys/param.h>
#include "router_globals.h"
#include "cJSON.h"

static const char *TAG = "IndexHandler";

char *appliedSSID = NULL;

bool isWrongHost(httpd_req_t *req)
{
    char *currentIP = getDefaultIPByNetmask();
    size_t buf_len = strlen(currentIP) + 1;
    char *host = malloc(buf_len);
    httpd_req_get_hdr_value_str(req, "Host", host, buf_len);
    bool out = strcmp(host, currentIP) != 0;
    free(host);
    free(currentIP);
    return out;
}

esp_err_t api_config_get_handler(httpd_req_t *req)
{
    if (isLocked())
    {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Locked");
    }

    httpd_resp_set_type(req, "application/json");
    closeHeader(req);

    cJSON *json = cJSON_CreateObject();

    // Basic AP configuration
    cJSON_AddStringToObject(json, "apSSID", ap_ssid);
    cJSON_AddStringToObject(json, "apPassword", ap_passwd);

    // SSID hidden setting
    int32_t ssidHidden = 0;
    get_config_param_int("ssid_hidden", &ssidHidden);
    cJSON_AddBoolToObject(json, "ssidHidden", ssidHidden == 1);

    // STA configuration
    if (appliedSSID != NULL && strlen(appliedSSID) > 0) {
        cJSON_AddStringToObject(json, "staSSID", appliedSSID);
        cJSON_AddStringToObject(json, "staPassword", "");
    } else {
        cJSON_AddStringToObject(json, "staSSID", ssid);
        cJSON_AddStringToObject(json, "staPassword", passwd);
    }

    // WiFi status
    char *db = NULL;
    char *textColor = NULL;
    fillInfoData(&db, &textColor);
    cJSON_AddStringToObject(json, "wifiStrength", db);
    cJSON_AddStringToObject(json, "wifiStatus", textColor);
    cJSON_AddBoolToObject(json, "wifiConnected", strcmp(db, "0") != 0);

    // Connection count
    uint16_t connect_count = getConnectCount();
    cJSON_AddNumberToObject(json, "connectCount", connect_count);

    // WPA2 Enterprise settings
    char *sta_identity = NULL;
    char *sta_user = NULL;
    size_t cert_len = 0;
    char *cert = NULL;
    
    get_config_param_str("sta_identity", &sta_identity);
    get_config_param_str("sta_user", &sta_user);
    get_config_param_blob("cer", &cert, &cert_len);

    bool wpa2Enabled = (sta_identity != NULL && strlen(sta_identity) != 0) || 
                       (sta_user != NULL && strlen(sta_user) != 0);
    
    cJSON_AddBoolToObject(json, "wpa2Enabled", wpa2Enabled);
    cJSON_AddStringToObject(json, "wpa2Identity", sta_identity ? sta_identity : "");
    cJSON_AddStringToObject(json, "wpa2User", sta_user ? sta_user : "");
    
    if (cert_len > 0) {
        char *cer = (char *)malloc(cert_len + 1);
        strncpy(cer, cert, cert_len);
        cer[cert_len] = '\0';
        cJSON_AddStringToObject(json, "wpa2Certificate", cer);
        free(cer);
    } else {
        cJSON_AddStringToObject(json, "wpa2Certificate", "");
    }

    // Lock settings
    char *lock_pass = NULL;
    get_config_param_str("lock_pass", &lock_pass);
    cJSON_AddBoolToObject(json, "hasLockPassword", lock_pass != NULL && strlen(lock_pass) > 0);

    // Scan result availability
    char *result_param = NULL;
    get_config_param_str("scan_result", &result_param);
    int32_t result_shown = 0;
    get_config_param_int("result_shown", &result_shown);
    cJSON_AddBoolToObject(json, "scanResultAvailable", result_param != NULL && result_shown < 3);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    
    free(json_string);
    cJSON_Delete(json);
    free(appliedSSID);
    appliedSSID = NULL;
    free(db);
    
    return ret;
}

esp_err_t api_config_post_handler(httpd_req_t *req)
{
    if (isLocked())
    {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Locked");
    }

    size_t content_len = req->content_len;
    char buf[content_len + 1];

    if (fill_post_buffer(req, buf, content_len) == ESP_OK)
    {
        buf[content_len] = '\0';
        char ssidParam[req->content_len];
        readUrlParameterIntoBuffer(buf, "ssid", ssidParam, req->content_len);

        if (strlen(ssidParam) > 0)
        {
            ESP_LOGI(TAG, "Found SSID parameter => %s", ssidParam);
            appliedSSID = malloc(strlen(ssidParam) + 1);
            strcpy(appliedSSID, ssidParam);
        }
    }

    httpd_resp_set_type(req, "application/json");
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);
    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    free(json_string);
    cJSON_Delete(json);
    return ret;
}