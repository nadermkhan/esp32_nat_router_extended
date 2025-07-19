#include "websocket_handlers.h"
#include "router_globals.h"
#include "helper.h"
#include "timer.h"
#include "scan.h"
#include "esp_wifi.h"
#include "esp_wifi_ap_get_sta_list.h"
#include "esp_ota_ops.h"
#include "esp_https_ota.h"
#include "nvs.h"
#include "cmd_nvs.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "WebSocketHandlers";

// Forward declarations
static void handle_get_config(websocket_client_t *client, cJSON *request);
static void handle_set_config(websocket_client_t *client, cJSON *request);
static void handle_get_clients(websocket_client_t *client, cJSON *request);
static void handle_get_portmap(websocket_client_t *client, cJSON *request);
static void handle_set_portmap(websocket_client_t *client, cJSON *request);
static void handle_get_advanced(websocket_client_t *client, cJSON *request);
static void handle_apply_config(websocket_client_t *client, cJSON *request);
static void handle_scan_wifi(websocket_client_t *client, cJSON *request);
static void handle_get_scan_results(websocket_client_t *client, cJSON *request);
static void handle_get_about(websocket_client_t *client, cJSON *request);
static void handle_get_ota(websocket_client_t *client, cJSON *request);
static void handle_ota_check(websocket_client_t *client, cJSON *request);
static void handle_ota_start(websocket_client_t *client, cJSON *request);
static void handle_ota_status(websocket_client_t *client, cJSON *request);
static void handle_unlock(websocket_client_t *client, cJSON *request);
static void handle_lock(websocket_client_t *client, cJSON *request);
static void handle_get_lock_status(websocket_client_t *client, cJSON *request);

static void send_error_response(websocket_client_t *client, const char *id, const char *message)
{
    cJSON *response = cJSON_CreateObject();
    if (id) cJSON_AddStringToObject(response, "id", id);
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", message);
    websocket_send_json(client->fd, response);
    cJSON_Delete(response);
}

static void send_success_response(websocket_client_t *client, const char *id, const char *action, cJSON *data)
{
    cJSON *response = cJSON_CreateObject();
    if (id) cJSON_AddStringToObject(response, "id", id);
    cJSON_AddBoolToObject(response, "success", true);
    if (action) cJSON_AddStringToObject(response, "action", action);
    if (data) cJSON_AddItemToObject(response, "data", data);
    websocket_send_json(client->fd, response);
    cJSON_Delete(response);
}

void handle_websocket_message(websocket_client_t *client, const char *message)
{
    cJSON *json = cJSON_Parse(message);
    if (!json) {
        send_error_response(client, NULL, "Invalid JSON");
        return;
    }

    cJSON *id_item = cJSON_GetObjectItem(json, "id");
    cJSON *action_item = cJSON_GetObjectItem(json, "action");
    
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;
    const char *action = action_item ? cJSON_GetStringValue(action_item) : NULL;

    if (!action) {
        send_error_response(client, id, "Missing action");
        cJSON_Delete(json);
        return;
    }

    ESP_LOGI(TAG, "Received action: %s from client fd: %d", action, client->fd);

    // Authentication check for protected actions
    if (!client->authenticated && 
        strcmp(action, "unlock") != 0 && 
        strcmp(action, "get_lock_status") != 0) {
        send_error_response(client, id, "Authentication required");
        cJSON_Delete(json);
        return;
    }

    // Route to appropriate handler
    if (strcmp(action, "get_config") == 0) {
        handle_get_config(client, json);
    } else if (strcmp(action, "set_config") == 0) {
        handle_set_config(client, json);
    } else if (strcmp(action, "get_clients") == 0) {
        handle_get_clients(client, json);
    } else if (strcmp(action, "get_portmap") == 0) {
        handle_get_portmap(client, json);
    } else if (strcmp(action, "set_portmap") == 0) {
        handle_set_portmap(client, json);
    } else if (strcmp(action, "get_advanced") == 0) {
        handle_get_advanced(client, json);
    } else if (strcmp(action, "apply_config") == 0) {
        handle_apply_config(client, json);
    } else if (strcmp(action, "scan_wifi") == 0) {
        handle_scan_wifi(client, json);
    } else if (strcmp(action, "get_scan_results") == 0) {
        handle_get_scan_results(client, json);
    } else if (strcmp(action, "get_about") == 0) {
        handle_get_about(client, json);
    } else if (strcmp(action, "get_ota") == 0) {
        handle_get_ota(client, json);
    } else if (strcmp(action, "ota_check") == 0) {
        handle_ota_check(client, json);
    } else if (strcmp(action, "ota_start") == 0) {
        handle_ota_start(client, json);
    } else if (strcmp(action, "ota_status") == 0) {
        handle_ota_status(client, json);
    } else if (strcmp(action, "unlock") == 0) {
        handle_unlock(client, json);
    } else if (strcmp(action, "lock") == 0) {
        handle_lock(client, json);
    } else if (strcmp(action, "get_lock_status") == 0) {
        handle_get_lock_status(client, json);
    } else {
        send_error_response(client, id, "Unknown action");
    }

    cJSON_Delete(json);
}

static void handle_get_config(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();

    // Basic AP configuration
    cJSON_AddStringToObject(data, "apSSID", ap_ssid);
    cJSON_AddStringToObject(data, "apPassword", ap_passwd);

    // SSID hidden setting
    int32_t ssidHidden = 0;
    get_config_param_int("ssid_hidden", &ssidHidden);
    cJSON_AddBoolToObject(data, "ssidHidden", ssidHidden == 1);

    // STA configuration
    cJSON_AddStringToObject(data, "staSSID", ssid);
    cJSON_AddStringToObject(data, "staPassword", passwd);

    // WiFi status
    char *db = NULL;
    char *textColor = NULL;
    fillInfoData(&db, &textColor);
    cJSON_AddStringToObject(data, "wifiStrength", db);
    cJSON_AddStringToObject(data, "wifiStatus", textColor);
    cJSON_AddBoolToObject(data, "wifiConnected", strcmp(db, "0") != 0);

    // Connection count
    uint16_t connect_count = getConnectCount();
    cJSON_AddNumberToObject(data, "connectCount", connect_count);

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
    
    cJSON_AddBoolToObject(data, "wpa2Enabled", wpa2Enabled);
    cJSON_AddStringToObject(data, "wpa2Identity", sta_identity ? sta_identity : "");
    cJSON_AddStringToObject(data, "wpa2User", sta_user ? sta_user : "");
    
    if (cert_len > 0) {
        char *cer = (char *)malloc(cert_len + 1);
        strncpy(cer, cert, cert_len);
        cer[cert_len] = '\0';
        cJSON_AddStringToObject(data, "wpa2Certificate", cer);
        free(cer);
    } else {
        cJSON_AddStringToObject(data, "wpa2Certificate", "");
    }

    // Lock settings
    char *lock_pass = NULL;
    get_config_param_str("lock_pass", &lock_pass);
    cJSON_AddBoolToObject(data, "hasLockPassword", lock_pass != NULL && strlen(lock_pass) > 0);

    // Scan result availability
    char *result_param = NULL;
    get_config_param_str("scan_result", &result_param);
    int32_t result_shown = 0;
    get_config_param_int("result_shown", &result_shown);
    cJSON_AddBoolToObject(data, "scanResultAvailable", result_param != NULL && result_shown < 3);

    send_success_response(client, id, "config", data);
    free(db);
}

static void handle_set_config(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    cJSON *data_item = cJSON_GetObjectItem(request, "data");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    if (!data_item) {
        send_error_response(client, id, "Missing data");
        return;
    }

    nvs_handle_t nvs;
    ESP_ERROR_CHECK(nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs));

    // AP Configuration
    cJSON *ap_ssid_item = cJSON_GetObjectItem(data_item, "apSSID");
    if (ap_ssid_item && cJSON_IsString(ap_ssid_item)) {
        ESP_ERROR_CHECK(nvs_set_str(nvs, "ap_ssid", cJSON_GetStringValue(ap_ssid_item)));
    }

    cJSON *ap_password_item = cJSON_GetObjectItem(data_item, "apPassword");
    if (ap_password_item && cJSON_IsString(ap_password_item)) {
        const char *ap_pass = cJSON_GetStringValue(ap_password_item);
        if (strlen(ap_pass) < 8) {
            nvs_erase_key(nvs, "ap_passwd");
        } else {
            ESP_ERROR_CHECK(nvs_set_str(nvs, "ap_passwd", ap_pass));
        }
    }

    cJSON *ssid_hidden_item = cJSON_GetObjectItem(data_item, "ssidHidden");
    if (ssid_hidden_item && cJSON_IsBool(ssid_hidden_item)) {
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "ssid_hidden", cJSON_IsTrue(ssid_hidden_item) ? 1 : 0));
    }

    // STA Configuration
    cJSON *sta_ssid_item = cJSON_GetObjectItem(data_item, "staSSID");
    if (sta_ssid_item && cJSON_IsString(sta_ssid_item)) {
        ESP_ERROR_CHECK(nvs_set_str(nvs, "ssid", cJSON_GetStringValue(sta_ssid_item)));
    }

    cJSON *sta_password_item = cJSON_GetObjectItem(data_item, "staPassword");
    if (sta_password_item && cJSON_IsString(sta_password_item)) {
        ESP_ERROR_CHECK(nvs_set_str(nvs, "passwd", cJSON_GetStringValue(sta_password_item)));
    }

    // WPA2 Enterprise
    cJSON *wpa2_identity_item = cJSON_GetObjectItem(data_item, "wpa2Identity");
    if (wpa2_identity_item && cJSON_IsString(wpa2_identity_item)) {
        const char *identity = cJSON_GetStringValue(wpa2_identity_item);
        if (strlen(identity) > 0) {
            ESP_ERROR_CHECK(nvs_set_str(nvs, "sta_identity", identity));
        } else {
            nvs_erase_key(nvs, "sta_identity");
        }
    }

    cJSON *wpa2_user_item = cJSON_GetObjectItem(data_item, "wpa2User");
    if (wpa2_user_item && cJSON_IsString(wpa2_user_item)) {
        const char *user = cJSON_GetStringValue(wpa2_user_item);
        if (strlen(user) > 0) {
            ESP_ERROR_CHECK(nvs_set_str(nvs, "sta_user", user));
        } else {
            nvs_erase_key(nvs, "sta_user");
        }
    }

    cJSON *wpa2_cert_item = cJSON_GetObjectItem(data_item, "wpa2Certificate");
    if (wpa2_cert_item && cJSON_IsString(wpa2_cert_item)) {
        const char *cert = cJSON_GetStringValue(wpa2_cert_item);
        if (strlen(cert) > 0) {
            nvs_erase_key(nvs, "cer");
            ESP_ERROR_CHECK(nvs_set_blob(nvs, "cer", cert, strlen(cert)));
        } else {
            nvs_erase_key(nvs, "cer");
        }
    }

    ESP_ERROR_CHECK(nvs_commit(nvs));
    nvs_close(nvs);

    cJSON *response_data = cJSON_CreateObject();
    cJSON_AddStringToObject(response_data, "message", "Configuration saved successfully");
    send_success_response(client, id, "config_saved", response_data);
}

static void handle_get_clients(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    wifi_sta_list_t wifi_sta_list;
    wifi_sta_mac_ip_list_t adapter_sta_list;
    memset(&wifi_sta_list, 0, sizeof(wifi_sta_list));
    memset(&adapter_sta_list, 0, sizeof(adapter_sta_list));
    esp_wifi_ap_get_sta_list(&wifi_sta_list);
    esp_wifi_ap_get_sta_list_with_ip(&wifi_sta_list, &adapter_sta_list);

    cJSON *data = cJSON_CreateObject();
    cJSON *clients_array = cJSON_CreateArray();

    if (wifi_sta_list.num > 0) {
        for (int i = 0; i < adapter_sta_list.num; i++) {
            cJSON *client_obj = cJSON_CreateObject();
            esp_netif_pair_mac_ip_t station = adapter_sta_list.sta[i];

            char str_ip[16];
            esp_ip4addr_ntoa(&(station.ip), str_ip, IP4ADDR_STRLEN_MAX);

            char currentMAC[18];
            sprintf(currentMAC, "%02x:%02x:%02x:%02x:%02x:%02x",
                    (unsigned int)station.mac[0], (unsigned int)station.mac[1], (unsigned int)station.mac[2],
                    (unsigned int)station.mac[3], (unsigned int)station.mac[4], (unsigned int)station.mac[5]);

            cJSON_AddNumberToObject(client_obj, "id", i + 1);
            cJSON_AddStringToObject(client_obj, "ip", str_ip);
            cJSON_AddStringToObject(client_obj, "mac", currentMAC);
            cJSON_AddItemToArray(clients_array, client_obj);
        }
    }

    cJSON_AddItemToObject(data, "clients", clients_array);
    cJSON_AddNumberToObject(data, "count", adapter_sta_list.num);

    send_success_response(client, id, "clients", data);
}

static void handle_get_portmap(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON *entries_array = cJSON_CreateArray();

    for (int i = 0; i < PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
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

    cJSON_AddItemToObject(data, "entries", entries_array);
    
    // Add IP prefix for frontend
    char *defaultIP = getDefaultIPByNetmask();
    char ip_prefix[strlen(defaultIP)];
    strncpy(ip_prefix, defaultIP, strlen(defaultIP) - 1);
    ip_prefix[strlen(defaultIP) - 1] = '\0';
    cJSON_AddStringToObject(data, "ipPrefix", ip_prefix);
    free(defaultIP);

    send_success_response(client, id, "portmap", data);
}

static void handle_set_portmap(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    cJSON *data_item = cJSON_GetObjectItem(request, "data");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    if (!data_item) {
        send_error_response(client, id, "Missing data");
        return;
    }

    cJSON *action_item = cJSON_GetObjectItem(data_item, "action");
    if (!action_item || !cJSON_IsString(action_item)) {
        send_error_response(client, id, "Missing action in data");
        return;
    }

    const char *action = cJSON_GetStringValue(action_item);
    cJSON *response_data = cJSON_CreateObject();

    if (strcmp(action, "add") == 0) {
        cJSON *protocol_item = cJSON_GetObjectItem(data_item, "protocol");
        cJSON *ext_port_item = cJSON_GetObjectItem(data_item, "externalPort");
        cJSON *int_ip_item = cJSON_GetObjectItem(data_item, "internalIP");
        cJSON *int_port_item = cJSON_GetObjectItem(data_item, "internalPort");

        if (!protocol_item || !ext_port_item || !int_ip_item || !int_port_item) {
            send_error_response(client, id, "Missing required fields for add");
            cJSON_Delete(response_data);
            return;
        }

        const char *protocol = cJSON_GetStringValue(protocol_item);
        uint16_t ext_port = (uint16_t)cJSON_GetNumberValue(ext_port_item);
        const char *int_ip = cJSON_GetStringValue(int_ip_item);
        uint16_t int_port = (uint16_t)cJSON_GetNumberValue(int_port_item);

        uint8_t tcp_udp = (strcmp(protocol, "TCP") == 0) ? PROTO_TCP : PROTO_UDP;
        uint32_t int_ip_addr = ipaddr_addr(int_ip);

        if (add_portmap(tcp_udp, ext_port, int_ip_addr, int_port) == ESP_OK) {
            cJSON_AddStringToObject(response_data, "message", "Port mapping added successfully");
            send_success_response(client, id, "portmap_added", response_data);
        } else {
            send_error_response(client, id, "Failed to add port mapping");
            cJSON_Delete(response_data);
        }

    } else if (strcmp(action, "delete") == 0) {
        cJSON *entry_id_item = cJSON_GetObjectItem(data_item, "entryId");
        if (!entry_id_item || !cJSON_IsString(entry_id_item)) {
            send_error_response(client, id, "Missing entryId for delete");
            cJSON_Delete(response_data);
            return;
        }

        const char *entry_id = cJSON_GetStringValue(entry_id_item);
        char entry_copy[strlen(entry_id) + 1];
        strcpy(entry_copy, entry_id);

        char *token = strtok(entry_copy, "_");
        uint8_t tcp_udp = (strcmp(token, "TCP") == 0) ? PROTO_TCP : PROTO_UDP;

        token = strtok(NULL, "_");
        uint16_t ext_port = (uint16_t)atoi(token);

        token = strtok(NULL, "_");
        uint32_t int_ip = ipaddr_addr(token);

        token = strtok(NULL, "_");
        uint16_t int_port = (uint16_t)atoi(token);

        if (del_portmap(tcp_udp, ext_port, int_ip, int_port) == ESP_OK) {
            cJSON_AddStringToObject(response_data, "message", "Port mapping deleted successfully");
            send_success_response(client, id, "portmap_deleted", response_data);
        } else {
            send_error_response(client, id, "Failed to delete port mapping");
            cJSON_Delete(response_data);
        }
    } else {
        send_error_response(client, id, "Invalid portmap action");
        cJSON_Delete(response_data);
    }
}

static void handle_get_advanced(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();

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
    cJSON_AddBoolToObject(data, "keepAlive", keepAlive == 1);
    cJSON_AddBoolToObject(data, "ledEnabled", ledDisabled == 0);
    cJSON_AddBoolToObject(data, "natEnabled", natDisabled == 0);
    cJSON_AddStringToObject(data, "hostname", hostName ? hostName : "");
    cJSON_AddNumberToObject(data, "octet", octet);

    // TX Power
    const char *txPowerLevel = "high";
    if (txPower < 34) txPowerLevel = "low";
    else if (txPower < 60) txPowerLevel = "medium";
    cJSON_AddStringToObject(data, "txPower", txPowerLevel);

    // Bandwidth
    cJSON_AddBoolToObject(data, "lowerBandwidth", bandwith == 1);

    // DNS settings
    esp_netif_dns_info_t dns;
    esp_netif_t *wifiSTA = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    char currentDNS[16] = "";
    if (esp_netif_get_dns_info(wifiSTA, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK) {
        sprintf(currentDNS, IPSTR, IP2STR(&(dns.ip.u_addr.ip4)));
    }
    cJSON_AddStringToObject(data, "currentDNS", currentDNS);

    char *customDNS = NULL;
    get_config_param_str("custom_dns", &customDNS);
    const char *dnsType = "default";
    if (customDNS != NULL) {
        if (strcmp(customDNS, "1.1.1.1") == 0) dnsType = "cloudflare";
        else if (strcmp(customDNS, "94.140.14.14") == 0) dnsType = "adguard";
        else dnsType = "custom";
    }
    cJSON_AddStringToObject(data, "dnsType", dnsType);
    cJSON_AddStringToObject(data, "customDNSIP", customDNS ? customDNS : "");

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

    cJSON_AddStringToObject(data, "currentMAC", currentMAC);
    cJSON_AddStringToObject(data, "defaultMAC", defaultMAC);

    char *macSetting = NULL;
    get_config_param_str("custom_mac", &macSetting);
    const char *macType = "default";
    if (macSetting && strcmp(macSetting, "random") == 0) {
        macType = "random";
    } else if (strcmp(currentMAC, defaultMAC) != 0) {
        macType = "custom";
    }
    cJSON_AddStringToObject(data, "macType", macType);

    // Netmask settings
    char *netmask = getNetmask();
    cJSON_AddStringToObject(data, "netmask", netmask);
    
    const char *netmaskType = "classc";
    if (strcmp(netmask, DEFAULT_NETMASK_CLASS_A) == 0) netmaskType = "classa";
    else if (strcmp(netmask, DEFAULT_NETMASK_CLASS_B) == 0) netmaskType = "classb";
    else if (strcmp(netmask, DEFAULT_NETMASK_CLASS_C) != 0) netmaskType = "custom";
    cJSON_AddStringToObject(data, "netmaskType", netmaskType);

    send_success_response(client, id, "advanced", data);
}

static void handle_apply_config(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    cJSON *data_item = cJSON_GetObjectItem(request, "data");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    if (!data_item) {
        send_error_response(client, id, "Missing data");
        return;
    }

    cJSON *func_item = cJSON_GetObjectItem(data_item, "function");
    if (!func_item || !cJSON_IsString(func_item)) {
        send_error_response(client, id, "Missing function parameter");
        return;
    }

    const char *function = cJSON_GetStringValue(func_item);
    cJSON *response_data = cJSON_CreateObject();
    bool success = true;
    const char *message = "Configuration applied successfully";

    if (strcmp(function, "config") == 0) {
        // Apply WiFi configuration - handled by handle_set_config
        message = "WiFi configuration applied successfully";
    } else if (strcmp(function, "erase") == 0) {
        // Erase configuration
        int argc = 2;
        char *argv[argc];
        argv[0] = "erase_namespace";
        argv[1] = PARAM_NAMESPACE;
        erase_ns(argc, argv);
        message = "Configuration erased successfully";
    } else if (strcmp(function, "advanced") == 0) {
        // Apply advanced configuration
        nvs_handle_t nvs;
        nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);

        // Process advanced settings from data_item
        cJSON *keepalive_item = cJSON_GetObjectItem(data_item, "keepAlive");
        if (keepalive_item && cJSON_IsBool(keepalive_item)) {
            ESP_ERROR_CHECK(nvs_set_i32(nvs, "keep_alive", cJSON_IsTrue(keepalive_item) ? 1 : 0));
        }

        cJSON *led_item = cJSON_GetObjectItem(data_item, "ledEnabled");
        if (led_item && cJSON_IsBool(led_item)) {
            ESP_ERROR_CHECK(nvs_set_i32(nvs, "led_disabled", cJSON_IsTrue(led_item) ? 0 : 1));
        }

        cJSON *nat_item = cJSON_GetObjectItem(data_item, "natEnabled");
        if (nat_item && cJSON_IsBool(nat_item)) {
            ESP_ERROR_CHECK(nvs_set_i32(nvs, "nat_disabled", cJSON_IsTrue(nat_item) ? 0 : 1));
        }

        cJSON *hostname_item = cJSON_GetObjectItem(data_item, "hostname");
        if (hostname_item && cJSON_IsString(hostname_item)) {
            const char *hostname = cJSON_GetStringValue(hostname_item);
            if (strlen(hostname) > 0) {
                ESP_ERROR_CHECK(nvs_set_str(nvs, "hostname", hostname));
            } else {
                nvs_erase_key(nvs, "hostname");
            }
        }

        cJSON *octet_item = cJSON_GetObjectItem(data_item, "octet");
        if (octet_item && cJSON_IsNumber(octet_item)) {
            int octet = (int)cJSON_GetNumberValue(octet_item);
            if (octet >= 0 && octet <= 255) {
                ESP_ERROR_CHECK(nvs_set_i32(nvs, "octet", octet));
            }
        }

        cJSON *txpower_item = cJSON_GetObjectItem(data_item, "txPower");
        if (txpower_item && cJSON_IsString(txpower_item)) {
            const char *txpower_str = cJSON_GetStringValue(txpower_item);
            int txpower = 80; // default high
            if (strcmp(txpower_str, "low") == 0) txpower = 20;
            else if (strcmp(txpower_str, "medium") == 0) txpower = 50;
            ESP_ERROR_CHECK(nvs_set_i32(nvs, "txpower", txpower));
        }

        cJSON *bandwidth_item = cJSON_GetObjectItem(data_item, "lowerBandwidth");
        if (bandwidth_item && cJSON_IsBool(bandwidth_item)) {
            if (cJSON_IsTrue(bandwidth_item)) {
                ESP_ERROR_CHECK(nvs_set_i32(nvs, "lower_bandwith", 1));
            } else {
                nvs_erase_key(nvs, "lower_bandwith");
            }
        }

        // DNS settings
        cJSON *dns_type_item = cJSON_GetObjectItem(data_item, "dnsType");
        if (dns_type_item && cJSON_IsString(dns_type_item)) {
            const char *dns_type = cJSON_GetStringValue(dns_type_item);
            if (strcmp(dns_type, "default") == 0) {
                nvs_erase_key(nvs, "custom_dns");
            } else if (strcmp(dns_type, "cloudflare") == 0) {
                ESP_ERROR_CHECK(nvs_set_str(nvs, "custom_dns", "1.1.1.1"));
            } else if (strcmp(dns_type, "adguard") == 0) {
                ESP_ERROR_CHECK(nvs_set_str(nvs, "custom_dns", "94.140.14.14"));
            } else if (strcmp(dns_type, "custom") == 0) {
                cJSON *custom_dns_item = cJSON_GetObjectItem(data_item, "customDNSIP");
                if (custom_dns_item && cJSON_IsString(custom_dns_item)) {
                    const char *custom_dns = cJSON_GetStringValue(custom_dns_item);
                    uint32_t ipasInt = esp_ip4addr_aton(custom_dns);
                    if (ipasInt != UINT32_MAX && ipasInt != 0) {
                        ESP_ERROR_CHECK(nvs_set_str(nvs, "custom_dns", custom_dns));
                    } else {
                        nvs_erase_key(nvs, "custom_dns");
                    }
                }
            }
        }

        // MAC settings
        cJSON *mac_type_item = cJSON_GetObjectItem(data_item, "macType");
        if (mac_type_item && cJSON_IsString(mac_type_item)) {
            const char *mac_type = cJSON_GetStringValue(mac_type_item);
            if (strcmp(mac_type, "default") == 0) {
                nvs_erase_key(nvs, "custom_mac");
            } else if (strcmp(mac_type, "random") == 0) {
                ESP_ERROR_CHECK(nvs_set_str(nvs, "custom_mac", "random"));
            } else if (strcmp(mac_type, "custom") == 0) {
                cJSON *custom_mac_item = cJSON_GetObjectItem(data_item, "customMAC");
                if (custom_mac_item && cJSON_IsString(custom_mac_item)) {
                    const char *custom_mac = cJSON_GetStringValue(custom_mac_item);
                    // Validate MAC format here if needed
                    ESP_ERROR_CHECK(nvs_set_str(nvs, "custom_mac", custom_mac));
                }
            }
        }

        // Netmask settings
        cJSON *netmask_type_item = cJSON_GetObjectItem(data_item, "netmaskType");
        if (netmask_type_item && cJSON_IsString(netmask_type_item)) {
            const char *netmask_type = cJSON_GetStringValue(netmask_type_item);
            if (strcmp(netmask_type, "classa") == 0) {
                ESP_ERROR_CHECK(nvs_set_str(nvs, "netmask", DEFAULT_NETMASK_CLASS_A));
            } else if (strcmp(netmask_type, "classb") == 0) {
                ESP_ERROR_CHECK(nvs_set_str(nvs, "netmask", DEFAULT_NETMASK_CLASS_B));
            } else if (strcmp(netmask_type, "classc") == 0) {
                ESP_ERROR_CHECK(nvs_set_str(nvs, "netmask", DEFAULT_NETMASK_CLASS_C));
            } else if (strcmp(netmask_type, "custom") == 0) {
                cJSON *custom_mask_item = cJSON_GetObjectItem(data_item, "customNetmask");
                if (custom_mask_item && cJSON_IsString(custom_mask_item)) {
                    const char *custom_mask = cJSON_GetStringValue(custom_mask_item);
                    if (is_valid_subnet_mask((char*)custom_mask)) {
                        ESP_ERROR_CHECK(nvs_set_str(nvs, "netmask", custom_mask));
                    } else {
                        ESP_ERROR_CHECK(nvs_set_str(nvs, "netmask", DEFAULT_NETMASK_CLASS_C));
                    }
                }
            }
        }

        nvs_commit(nvs);
        nvs_close(nvs);
        message = "Advanced configuration applied successfully";
    } else {
        success = false;
        message = "Invalid function parameter";
    }

    cJSON_AddBoolToObject(response_data, "success", success);
    cJSON_AddStringToObject(response_data, "message", message);

    if (success) {
        cJSON_AddBoolToObject(response_data, "restarting", true);
        cJSON_AddNumberToObject(response_data, "restartDelay", 1);
        restartByTimerinS(1);
    }

    send_success_response(client, id, "apply_result", response_data);
}

static void handle_scan_wifi(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    // Start the scan
    fillNodes();

    cJSON *response_data = cJSON_CreateObject();
    cJSON_AddStringToObject(response_data, "message", "WiFi scan started");

    char *defaultIP = getDefaultIPByNetmask();
    cJSON_AddStringToObject(response_data, "redirectUrl", defaultIP);
    free(defaultIP);

    send_success_response(client, id, "scan_started", response_data);
}

static void handle_get_scan_results(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON *networks_array = cJSON_CreateArray();

    char *result_param = NULL;
    get_config_param_str("scan_result", &result_param);
    
    if (result_param == NULL) {
        cJSON_AddItemToObject(data, "networks", networks_array);
        cJSON_AddBoolToObject(data, "hasResults", false);
    } else {
        char *end_str;
        char *row = strtok_r(result_param, "\x05", &end_str);
        while (row != NULL) {
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
        cJSON_AddItemToObject(data, "networks", networks_array);
        cJSON_AddBoolToObject(data, "hasResults", true);
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

    send_success_response(client, id, "scan_results", data);
}

static void handle_get_about(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    const char *project_version = get_project_version();
    const char *project_build_date = get_project_build_date();

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "version", project_version);
    cJSON_AddStringToObject(data, "hash", GLOBAL_HASH);
    cJSON_AddStringToObject(data, "buildDate", project_build_date);

    send_success_response(client, id, "about", data);
}

// OTA related handlers (simplified versions)
static void handle_get_ota(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    // This would need the OTA variables from otahandler.c
    extern char latest_version[50];
    extern char changelog[400];
    extern char chip_type[30];
    extern bool otaRunning;

    if (strlen(latest_version) == 0) {
        strcpy(latest_version, "Not determined yet");
        strcpy(changelog, "Not determined yet");
    }

    determineChipType(chip_type);
    const char *project_version = get_project_version();

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "currentVersion", project_version);
    cJSON_AddStringToObject(data, "latestVersion", latest_version);
    cJSON_AddStringToObject(data, "changelog", changelog);
    cJSON_AddStringToObject(data, "chipType", chip_type);
    cJSON_AddBoolToObject(data, "otaRunning", otaRunning);

    send_success_response(client, id, "ota_info", data);
}

static void handle_ota_check(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    // Call the update version function from otahandler.c
    extern void updateVersion(void);
    extern char latest_version[50];
    extern char changelog[400];
    
    updateVersion();

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "latestVersion", latest_version);
    cJSON_AddStringToObject(data, "changelog", changelog);

    send_success_response(client, id, "ota_check_result", data);
}

static void handle_ota_start(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    // Call the start OTA function from otahandler.c
    extern void start_ota_update(void);
    extern bool otaRunning;
    extern char otalog[2000];
    extern char resultLog[110];
    
    otalog[0] = '\0';
    resultLog[0] = '\0';
    otaRunning = true;
    start_ota_update();

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "message", "OTA update started");

    send_success_response(client, id, "ota_started", data);
}

static void handle_ota_status(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    extern bool otaRunning;
    extern bool finished;
    extern int progressInt;
    extern char progressLabel[20];
    extern char otalog[2000];
    extern char resultLog[110];

    cJSON *data = cJSON_CreateObject();
    cJSON_AddBoolToObject(data, "otaRunning", otaRunning);
    cJSON_AddBoolToObject(data, "finished", finished);
    cJSON_AddNumberToObject(data, "progress", progressInt);
    cJSON_AddStringToObject(data, "progressLabel", progressLabel);
    cJSON_AddStringToObject(data, "log", otalog);
    cJSON_AddStringToObject(data, "result", resultLog);

    if (finished) {
        restartByTimerinS(3);
    }

    send_success_response(client, id, "ota_status", data);
}

static void handle_unlock(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    cJSON *data_item = cJSON_GetObjectItem(request, "data");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    if (!data_item) {
        send_error_response(client, id, "Missing data");
        return;
    }

    cJSON *password_item = cJSON_GetObjectItem(data_item, "password");
    if (!password_item || !cJSON_IsString(password_item)) {
        send_error_response(client, id, "Missing password");
        return;
    }

    const char *password = cJSON_GetStringValue(password_item);
    char *lock_pass = NULL;
    get_config_param_str("lock_pass", &lock_pass);

    if (lock_pass && strcmp(lock_pass, password) == 0) {
        client->authenticated = true;
        cJSON *data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "message", "Unlocked successfully");
        send_success_response(client, id, "unlocked", data);
    } else {
        send_error_response(client, id, "Invalid password");
    }
}

static void handle_lock(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    cJSON *data_item = cJSON_GetObjectItem(request, "data");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    if (!data_item) {
        send_error_response(client, id, "Missing data");
        return;
    }

    cJSON *password_item = cJSON_GetObjectItem(data_item, "password");
    cJSON *password2_item = cJSON_GetObjectItem(data_item, "password2");

    if (!password_item || !password2_item || 
        !cJSON_IsString(password_item) || !cJSON_IsString(password2_item)) {
        send_error_response(client, id, "Missing password fields");
        return;
    }

    const char *password = cJSON_GetStringValue(password_item);
    const char *password2 = cJSON_GetStringValue(password2_item);

    if (strcmp(password, password2) == 0) {
        nvs_handle_t nvs;
        nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
        nvs_set_str(nvs, "lock_pass", password);
        nvs_commit(nvs);
        nvs_close(nvs);

        if (strlen(password) > 0) {
            lockUI();
            client->authenticated = false;
        }

        cJSON *data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "message", "Password updated successfully");
        cJSON_AddBoolToObject(data, "locked", strlen(password) > 0);
        send_success_response(client, id, "lock_updated", data);
    } else {
        send_error_response(client, id, "Passwords do not match");
    }
}

static void handle_get_lock_status(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON_AddBoolToObject(data, "locked", isLocked());
    cJSON_AddBoolToObject(data, "authenticated", client->authenticated);
    
    char *lock_pass = NULL;
    get_config_param_str("lock_pass", &lock_pass);
    cJSON_AddBoolToObject(data, "hasPassword", lock_pass != NULL && strlen(lock_pass) > 0);

    send_success_response(client, id, "lock_status", data);
}
    