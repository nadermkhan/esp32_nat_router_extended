#include "handler.h"
#include "timer.h"
#include <sys/param.h>
#include "nvs.h"
#include "cmd_nvs.h"
#include "router_globals.h"
#include "esp_wifi.h"
#include "esp_wifi_ap_get_sta_list.h"
#include "cJSON.h"

static const char *TAG = "ClientsHandler";

esp_err_t api_clients_get_handler(httpd_req_t *req)
{
    if (isLocked())
    {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Locked");
    }

    httpd_resp_set_type(req, "application/json");
    closeHeader(req);

    wifi_sta_list_t wifi_sta_list;
    wifi_sta_mac_ip_list_t adapter_sta_list;
    memset(&wifi_sta_list, 0, sizeof(wifi_sta_list));
    memset(&adapter_sta_list, 0, sizeof(adapter_sta_list));
    esp_wifi_ap_get_sta_list(&wifi_sta_list);
    esp_wifi_ap_get_sta_list_with_ip(&wifi_sta_list, &adapter_sta_list);

    cJSON *json = cJSON_CreateObject();
    cJSON *clients_array = cJSON_CreateArray();

    if (wifi_sta_list.num > 0)
    {
        for (int i = 0; i < adapter_sta_list.num; i++)
        {
            cJSON *client = cJSON_CreateObject();
            esp_netif_pair_mac_ip_t station = adapter_sta_list.sta[i];

            char str_ip[16];
            esp_ip4addr_ntoa(&(station.ip), str_ip, IP4ADDR_STRLEN_MAX);

            char currentMAC[18];
sprintf(currentMAC, "%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned int)station.mac[0], (unsigned int)station.mac[1], (unsigned int)station.mac[2],
        (unsigned int)station.mac[3], (unsigned int)station.mac[4], (unsigned int)station.mac[5]);

            cJSON_AddNumberToObject(client, "id", i + 1);
            cJSON_AddStringToObject(client, "ip", str_ip);
            cJSON_AddStringToObject(client, "mac", currentMAC);
            cJSON_AddItemToArray(clients_array, client);
        }
    }

    cJSON_AddItemToObject(json, "clients", clients_array);
    cJSON_AddNumberToObject(json, "count", adapter_sta_list.num);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    
    free(json_string);
    cJSON_Delete(json);
    ESP_LOGI(TAG, "API: Requesting clients data");
    return ret;
}
