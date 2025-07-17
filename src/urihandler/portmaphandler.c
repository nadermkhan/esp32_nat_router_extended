#include "handler.h"
#include "timer.h"
#include <sys/param.h>
#include "nvs.h"
#include "cmd_nvs.h"
#include "router_globals.h"
#include "esp_wifi.h"
#include "esp_wifi_ap_get_sta_list.h"
#include "cJSON.h"

static const char *TAG = "PortMapHandler";

esp_err_t api_portmap_get_handler(httpd_req_t *req)
{
    if (isLocked())
    {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Locked");
    }

    httpd_resp_set_type(req, "application/json");
    closeHeader(req);

    cJSON *json = cJSON_CreateObject();
    cJSON *entries_array = cJSON_CreateArray();

    for (int i = 0; i < PORTMAP_MAX; i++)
    {
        if (portmap_tab[i].valid)
        {
            cJSON *entry = cJSON_CreateObject();
            
            const char *protocol = (portmap_tab[i].proto == PROTO_TCP) ? "TCP" : "UDP";
            cJSON_AddStringToObject(entry, "protocol", protocol);
            cJSON_AddNumberToObject(entry, "externalPort", portmap_tab[i].mport);
            
            esp_ip4_addr_t addr;
            addr.addr = portmap_tab[i].daddr;
            char ip_str[16];
            sprintf(ip_str, IPSTR, IP2STR(&addr));
            cJSON_AddStringToObject(entry, "internalIP", ip_str);
            cJSON_AddNumberToObject(entry, "internalPort", portmap_tab[i].dport);
            
            char delParam[50];
            sprintf(delParam, "%s_%hu_%s_%hu", protocol, portmap_tab[i].mport, ip_str, portmap_tab[i].dport);
            cJSON_AddStringToObject(entry, "id", delParam);
            
            cJSON_AddItemToArray(entries_array, entry);
        }
    }

    cJSON_AddItemToObject(json, "entries", entries_array);
    
    // Add IP prefix for frontend
    char *defaultIP = getDefaultIPByNetmask();
    char ip_prefix[strlen(defaultIP)];
    strncpy(ip_prefix, defaultIP, strlen(defaultIP) - 1);
    ip_prefix[strlen(defaultIP) - 1] = '\0';
    cJSON_AddStringToObject(json, "ipPrefix", ip_prefix);
    free(defaultIP);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    
    free(json_string);
    cJSON_Delete(json);
    ESP_LOGI(TAG, "API: Requesting portmap data");
    return ret;
}

void addPortmapEntry(char *urlContent)
{
    size_t contentLength = 64;
    char param[contentLength];
    readUrlParameterIntoBuffer(urlContent, "protocol", param, contentLength);
    uint8_t tcp_udp;
    if (strcmp(param, "tcp") == 0)
    {
        tcp_udp = PROTO_TCP;
    }
    else
    {
        tcp_udp = PROTO_UDP;
    }
    readUrlParameterIntoBuffer(urlContent, "eport", param, contentLength);
    char *endptr;
    uint16_t ext_port = (uint16_t)strtoul(param, &endptr, 10);
    if (ext_port < 1 || *endptr != '\0')
    {
        ESP_LOGW(TAG, "External port out of range");
        return;
    }

    readUrlParameterIntoBuffer(urlContent, "ip", param, contentLength);
    char *defaultIP = getDefaultIPByNetmask();
    char resultIP[strlen(defaultIP) + strlen(param)];
    strncpy(resultIP, defaultIP, strlen(defaultIP) - 1);
    resultIP[strlen(defaultIP) - 1] = '\0';
    strcat(resultIP, param);
    free(defaultIP);
    uint32_t int_ip = ipaddr_addr(resultIP);
    if (int_ip == IPADDR_NONE)
    {
        ESP_LOGW(TAG, "Invalid IP");
        return;
    }
    readUrlParameterIntoBuffer(urlContent, "iport", param, contentLength);
    uint16_t int_port = (uint16_t)strtoul(param, &endptr, 10);

    if (int_port < 1 || *endptr != '\0')
    {
        ESP_LOGW(TAG, "Internal port out of range");
        return;
    }

    add_portmap(tcp_udp, ext_port, int_ip, int_port);
}

void delPortmapEntry(char *urlContent)
{
    size_t contentLength = 64;
    char param[contentLength];
    readUrlParameterIntoBuffer(urlContent, "entry", param, contentLength);

    const char delimiter[] = "_";

    char *token = strtok(param, delimiter);
    uint8_t tcp_udp;
    if (strcmp(token, "TCP") == 0)
    {
        tcp_udp = PROTO_TCP;
    }
    else
    {
        tcp_udp = PROTO_UDP;
    }

    token = strtok(NULL, delimiter);
    char *endptr;
    uint16_t ext_port = (uint16_t)strtoul(token, &endptr, 10);
    if (ext_port < 1 || *endptr != '\0')
    {
        ESP_LOGW(TAG, "External port out of range");
        return;
    }
    token = strtok(NULL, delimiter);
    uint32_t int_ip = ipaddr_addr(token);
    if (int_ip == IPADDR_NONE)
    {
        ESP_LOGW(TAG, "Invalid IP");
        return;
    }

    token = strtok(NULL, delimiter);
    uint16_t int_port = (uint16_t)strtoul(token, &endptr, 10);

    if (int_port < 1 || *endptr != '\0')
    {
        ESP_LOGW(TAG, "Internal port out of range");
        return;
    }

    del_portmap(tcp_udp, ext_port, int_ip, int_port);
}

esp_err_t api_portmap_post_handler(httpd_req_t *req)
{
    if (isLocked())
    {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Locked");
    }

    size_t content_len = req->content_len;
    char buf[content_len + 1];

    httpd_resp_set_type(req, "application/json");
    cJSON *json = cJSON_CreateObject();

    if (fill_post_buffer(req, buf, content_len) == ESP_OK)
    {
        buf[content_len] = '\0';
        char funcParam[4];

        ESP_LOGI(TAG, "getting content %s", buf);

        readUrlParameterIntoBuffer(buf, "func", funcParam, 4);

        if (strcmp(funcParam, "add") == 0)
        {
            addPortmapEntry(buf);
            cJSON_AddBoolToObject(json, "success", true);
            cJSON_AddStringToObject(json, "message", "Port mapping added successfully");
        }
        else if (strcmp(funcParam, "del") == 0)
        {
            delPortmapEntry(buf);
            cJSON_AddBoolToObject(json, "success", true);
            cJSON_AddStringToObject(json, "message", "Port mapping deleted successfully");
        }
        else
        {
            cJSON_AddBoolToObject(json, "success", false);
            cJSON_AddStringToObject(json, "message", "Invalid function parameter");
        }
    }
    else
    {
        cJSON_AddBoolToObject(json, "success", false);
        cJSON_AddStringToObject(json, "message", "Failed to read request data");
    }

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    free(json_string);
    cJSON_Delete(json);
    return ret;
}