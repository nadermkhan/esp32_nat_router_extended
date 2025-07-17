#include "handler.h"
#include "scan.h"
#include "router_globals.h"
#include "cJSON.h"

static const char *TAG = "ScanHandler";

void fillInfoData(char **db, char **textColor)
{
    *db = realloc(*db, 5);
    wifi_ap_record_t apinfo;
    memset(&apinfo, 0, sizeof(apinfo));
    if (esp_wifi_sta_get_ap_info(&apinfo) == ESP_OK)
    {
        sprintf(*db, "%d", apinfo.rssi);
        *textColor = findTextColorForSSID(apinfo.rssi);
        ESP_LOGD(TAG, "RSSI: %d", apinfo.rssi);
        ESP_LOGD(TAG, "SSID: %s", apinfo.ssid);
    }
    else
    {
        sprintf(*db, "%d", 0);
        *textColor = "danger";
    }
}

esp_err_t api_scan_start_post_handler(httpd_req_t *req)
{
    if (isLocked())
    {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Locked");
    }

    httpd_resp_set_type(req, "application/json");
    closeHeader(req);

    // Start the scan
    fillNodes();

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);
    cJSON_AddStringToObject(json, "message", "WiFi scan started");

    char *defaultIP = getDefaultIPByNetmask();
    cJSON_AddStringToObject(json, "redirectUrl", defaultIP);
    free(defaultIP);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    free(json_string);
    cJSON_Delete(json);
    ESP_LOGI(TAG, "API: WiFi scan started");
    return ret;
}