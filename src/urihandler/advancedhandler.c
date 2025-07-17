#include "handler.h"
#include <sys/param.h>
#include "dhcpserver/dhcpserver.h"
#include "router_globals.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_err.h"
#include "cJSON.h"

static const char *TAG = "AdvancedHandler";

esp_err_t api_advanced_get_handler(httpd_req_t *req)
{
    if (isLocked())
    {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Locked");
    }

    httpd_resp_set_type(req, "application/json");
    closeHeader(req);

    cJSON *json = cJSON_CreateObject();

    // Get all configuration values
    int32_t keepAlive = 0;
    int32_t ledDisabled = 0;
    int32_t natDisabled = 0;
    char *hostName = NULL;
    int32_t octet = 4;
    int32_t txPower = 80;
    int32_t bandwith = 0;

    get_config_param_int("keep_alive", &keepAlive);
    get_config_param_int("led_disabled", &ledDisabled);
    get_config_param_int("nat_disabled", &natDisabled);
    get_config_param_str("hostname", &hostName);
    get_config_param_int("octet", &octet);
    get_config_param_int("txpower", &txPower);
    get_config_param_int("lower_bandwith", &bandwith);

    // Add basic settings
    cJSON_AddBoolToObject(json, "keepAlive", keepAlive == 1);
    cJSON_AddBoolToObject(json, "ledEnabled", ledDisabled == 0);
    cJSON_AddBoolToObject(json, "natEnabled", natDisabled == 0);
    cJSON_AddStringToObject(json, "hostname", hostName ? hostName : "");
    cJSON_AddNumberToObject(json, "octet", octet);

    // TX Power
    const char *txPowerLevel = "high";
    if (txPower < 34) txPowerLevel = "low";
    else if (txPower < 60) txPowerLevel = "medium";
    cJSON_AddStringToObject(json, "txPower", txPowerLevel);

    // Bandwidth
    cJSON_AddBoolToObject(json, "lowerBandwidth", bandwith == 1);

    // DNS settings
    esp_netif_dns_info_t dns;
    esp_netif_t *wifiSTA = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    char currentDNS[16] = "";
    if (esp_netif_get_dns_info(wifiSTA, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK)
    {
        sprintf(currentDNS, IPSTR, IP2STR(&(dns.ip.u_addr.ip4)));
    }
    cJSON_AddStringToObject(json, "currentDNS", currentDNS);

    char *customDNS = NULL;
    get_config_param_str("custom_dns", &customDNS);
    const char *dnsType = "default";
    if (customDNS != NULL) {
        if (strcmp(customDNS, "1.1.1.1") == 0) dnsType = "cloudflare";
        else if (strcmp(customDNS, "94.140.14.14") == 0) dnsType = "adguard";
        else dnsType = "custom";
    }
    cJSON_AddStringToObject(json, "dnsType", dnsType);
    cJSON_AddStringToObject(json, "customDNSIP", customDNS ? customDNS : "");

    // MAC settings
    uint8_t base_mac_addr[6] = {0};
    uint8_t default_mac_addr[6] = {0};
    ESP_ERROR_CHECK(esp_base_mac_addr_get(base_mac_addr));
    ESP_ERROR_CHECK(esp_efuse_mac_get_default(default_mac_addr));

    char currentMAC[18];
    char defaultMAC[18];
    sprintf(currentMAC, "%02x:%02x:%02x:%02x:%02x:%02x", 
            base_mac_addr[0], base_mac_addr[1], base_mac_addr[2], 
            base_mac_addr[3], base_mac_addr[4], base_mac_addr[5]);
    sprintf(defaultMAC, "%02x:%02x:%02x:%02x:%02x:%02x", 
            default_mac_addr[0], default_mac_addr[1], default_mac_addr[2], 
            default_mac_addr[3], default_mac_addr[4], default_mac_addr[5]);

    cJSON_AddStringToObject(json, "currentMAC", currentMAC);
    cJSON_AddStringToObject(json, "defaultMAC", defaultMAC);

    char *macSetting = NULL;
    get_config_param_str("custom_mac", &macSetting);
    const char *macType = "default";
    if (macSetting && strcmp(macSetting, "random") == 0) {
        macType = "random";
    } else if (strcmp(currentMAC, defaultMAC) != 0) {
        macType = "custom";
    }
    cJSON_AddStringToObject(json, "macType", macType);

    // Netmask settings
    char *netmask = getNetmask();
    cJSON_AddStringToObject(json, "netmask", netmask);
    
    const char *netmaskType = "classc";
    if (strcmp(netmask, DEFAULT_NETMASK_CLASS_A) == 0) netmaskType = "classa";
    else if (strcmp(netmask, DEFAULT_NETMASK_CLASS_B) == 0) netmaskType = "classb";
    else if (strcmp(netmask, DEFAULT_NETMASK_CLASS_C) != 0) netmaskType = "custom";
    cJSON_AddStringToObject(json, "netmaskType", netmaskType);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    
    free(json_string);
    cJSON_Delete(json);
    return ret;
}