#include "handler.h"
#include <esp_wifi.h>
#include "nvs.h"
#include "cmd_nvs.h"
#include "router_globals.h"
#include "cJSON.h"

static const char *TAG = "ResultHandler";

char *findTextColorForSSID(int8_t rssi)
{
    char *color;
    if (rssi >= -50)
    {
        color = "success";
    }
    else if (rssi >= -70)
    {
        color = "info";
    }
    else
    {
        color = "warning";
    }
    return color;
}

esp_err_t api_scan_result_get_handler(httpd_req_t *req)
{
    if (isLocked())
    {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Locked");
    }

    httpd_resp_set_type(req, "application/json");
    closeHeader(req);

    cJSON *json = cJSON_CreateObject();
    cJSON *networks_array = cJSON_CreateArray();

    char *result_param = NULL;
    get_config_param_str("scan_result", &result_param);
    
    if (result_param == NULL)
    {
        cJSON_AddItemToObject(json, "networks", networks_array);
        cJSON_AddBoolToObject(json, "hasResults", false);
    }
    else
    {
        char *end_str;
        char *row = strtok_r(result_param, "\x05", &end_str);
        while (row != NULL)
        {
            cJSON *network = cJSON_CreateObject();
            char *ssid = strtok(row, "\x03");
            char *rssi = strtok(NULL, "\x03");

            if (ssid && rssi) {
                int rssi_value = atoi(rssi);
                char *css = findTextColorForSSID(rssi_value);
                
                cJSON_AddStringToObject(network, "ssid", ssid);
                cJSON_AddNumberToObject(network, "rssi", rssi_value);
                cJSON_AddStringToObject(network, "strength", css);
                cJSON_AddItemToArray(networks_array, network);
            }

            row = strtok_r(NULL, "\x05", &end_str);
        }
        cJSON_AddItemToObject(json, "networks", networks_array);
        cJSON_AddBoolToObject(json, "hasResults", true);
    }

    // Update result shown counter
    nvs_handle_t nvs;
    nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    int32_t result_shown = 0;
    get_config_param_int("result_shown", &result_shown);
    nvs_set_i32(nvs, "result_shown", ++result_shown);
    ESP_LOGI(TAG, "Result shown %ld times", result_shown);
    nvs_commit(nvs);
    nvs_close(nvs);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    free(json_string);
    cJSON_Delete(json);
    return ret;
}