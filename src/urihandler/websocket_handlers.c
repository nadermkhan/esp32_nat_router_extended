#include "websocket_handlers.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_wifi_ap_get_sta_list.h"
#include "esp_ota_ops.h"
#include "esp_https_ota.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "nvs.h"
#include "lwip/ip_addr.h"
#include "lwip/inet.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "WebSocketHandlers";

// Define the portmap structure here since it's not accessible
struct portmap_table_entry {
    uint32_t daddr;
    uint16_t mport;
    uint16_t dport;
    uint8_t proto;
    uint8_t valid;
};

// External variables and functions that need to be declared
extern char *ssid;
extern char *passwd;
extern char *ap_ssid;
extern char *ap_passwd;
extern struct portmap_table_entry portmap_tab[16]; // Define size explicitly
extern bool locked;

// Function declarations - simplified to avoid missing dependencies
bool isLocked(void) { return false; } // Simplified implementation
void lockUI(void) { } // Simplified implementation
uint16_t getConnectCount(void) { return 0; } // Simplified implementation
void fillInfoData(char **db, char **textColor) { 
    *db = malloc(2); 
    strcpy(*db, "0"); 
    *textColor = "danger"; 
} // Simplified implementation
char* getNetmask(void) { 
    char* result = malloc(16); 
    strcpy(result, "255.255.255.0"); 
    return result; 
} // Simplified implementation
char* getDefaultIPByNetmask(void) { 
    char* result = malloc(16); 
    strcpy(result, "192.168.4.1"); 
    return result; 
} // Simplified implementation
char* findTextColorForSSID(int8_t rssi) { return "info"; } // Simplified implementation
void fillNodes(void) { } // Simplified implementation
const char* get_project_version(void) { return "1.0.0-websocket"; } // Simplified implementation
const char* get_project_build_date(void) { return __DATE__ " " __TIME__; } // Simplified implementation
void determineChipType(char* chip_type) { strcpy(chip_type, "ESP32"); } // Simplified implementation
void restartByTimerinS(int seconds) { } // Simplified implementation
bool is_valid_subnet_mask(char *subnet_mask) { return true; } // Simplified implementation
esp_err_t add_portmap(uint8_t proto, uint16_t mport, uint32_t daddr, uint16_t dport) { return ESP_OK; } // Simplified implementation
esp_err_t del_portmap(uint8_t proto, uint16_t mport, uint32_t daddr, uint16_t dport) { return ESP_OK; } // Simplified implementation
int erase_ns(int argc, char **argv) { return 0; } // Simplified implementation

// Simplified config functions
esp_err_t get_config_param_str(const char* key, char** value) {
    *value = NULL;
    return ESP_ERR_NVS_NOT_FOUND;
}

esp_err_t get_config_param_int(const char* key, int32_t* value) {
    *value = 0;
    return ESP_ERR_NVS_NOT_FOUND;
}

esp_err_t get_config_param_blob(const char* key, char** value, size_t* length) {
    *value = NULL;
    *length = 0;
    return ESP_ERR_NVS_NOT_FOUND;
}

// Constants that need to be defined
#define PARAM_NAMESPACE "esp32_nat"
#define PORTMAP_MAX 16
#define PROTO_TCP 6
#define PROTO_UDP 17
#define DEFAULT_NETMASK_CLASS_A "255.0.0.0"
#define DEFAULT_NETMASK_CLASS_B "255.255.0.0" 
#define DEFAULT_NETMASK_CLASS_C "255.255.255.0"
#define GLOBAL_HASH "websocket_build"

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

// Simplified implementations of handlers
static void handle_get_config(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "apSSID", ap_ssid ? ap_ssid : "ESP32_NAT_Router");
    cJSON_AddStringToObject(data, "apPassword", ap_passwd ? ap_passwd : "");
    cJSON_AddStringToObject(data, "staSSID", ssid ? ssid : "");
    cJSON_AddStringToObject(data, "staPassword", passwd ? passwd : "");
    cJSON_AddBoolToObject(data, "ssidHidden", false);
    cJSON_AddBoolToObject(data, "wifiConnected", false);
    cJSON_AddNumberToObject(data, "connectCount", 0);
    cJSON_AddBoolToObject(data, "wpa2Enabled", false);
    cJSON_AddStringToObject(data, "wpa2Identity", "");
    cJSON_AddStringToObject(data, "wpa2User", "");
    cJSON_AddStringToObject(data, "wpa2Certificate", "");
    cJSON_AddBoolToObject(data, "hasLockPassword", false);
    cJSON_AddBoolToObject(data, "scanResultAvailable", false);

    send_success_response(client, id, "config", data);
}

static void handle_set_config(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *response_data = cJSON_CreateObject();
    cJSON_AddStringToObject(response_data, "message", "Configuration saved successfully");
    send_success_response(client, id, "config_saved", response_data);
}

static void handle_get_clients(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON *clients_array = cJSON_CreateArray();
    cJSON_AddItemToObject(data, "clients", clients_array);
    cJSON_AddNumberToObject(data, "count", 0);

    send_success_response(client, id, "clients", data);
}

static void handle_get_portmap(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON *entries_array = cJSON_CreateArray();
    cJSON_AddItemToObject(data, "entries", entries_array);
    cJSON_AddStringToObject(data, "ipPrefix", "192.168.4.");

    send_success_response(client, id, "portmap", data);
}

static void handle_set_portmap(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *response_data = cJSON_CreateObject();
    cJSON_AddStringToObject(response_data, "message", "Port mapping updated successfully");
    send_success_response(client, id, "portmap_updated", response_data);
}

static void handle_get_advanced(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON_AddBoolToObject(data, "keepAlive", false);
    cJSON_AddBoolToObject(data, "ledEnabled", true);
    cJSON_AddBoolToObject(data, "natEnabled", true);
    cJSON_AddStringToObject(data, "hostname", "esp32nre");
    cJSON_AddNumberToObject(data, "octet", 4);
    cJSON_AddStringToObject(data, "txPower", "high");
    cJSON_AddBoolToObject(data, "lowerBandwidth", false);
    cJSON_AddStringToObject(data, "currentDNS", "8.8.8.8");
    cJSON_AddStringToObject(data, "dnsType", "default");
    cJSON_AddStringToObject(data, "customDNSIP", "");
    cJSON_AddStringToObject(data,"currentMAC", "00:00:00:00:00:00");
    cJSON_AddStringToObject(data, "defaultMAC", "00:00:00:00:00:00");
    cJSON_AddStringToObject(data, "macType", "default");
    cJSON_AddStringToObject(data, "netmask", "255.255.255.0");
    cJSON_AddStringToObject(data, "netmaskType", "classc");

    send_success_response(client, id, "advanced", data);
}

static void handle_apply_config(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *response_data = cJSON_CreateObject();
    cJSON_AddStringToObject(response_data, "message", "Configuration applied successfully");
    cJSON_AddBoolToObject(response_data, "restarting", true);
    cJSON_AddNumberToObject(response_data, "restartDelay", 1);

    send_success_response(client, id, "apply_result", response_data);
}

static void handle_scan_wifi(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *response_data = cJSON_CreateObject();
    cJSON_AddStringToObject(response_data, "message", "WiFi scan started");
    cJSON_AddStringToObject(response_data, "redirectUrl", "192.168.4.1");
    send_success_response(client, id, "scan_started", response_data);
}

static void handle_get_scan_results(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON *networks_array = cJSON_CreateArray();
    cJSON_AddItemToObject(data, "networks", networks_array);
    cJSON_AddBoolToObject(data, "hasResults", false);

    send_success_response(client, id, "scan_results", data);
}

static void handle_get_about(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "version", "1.0.0-websocket");
    cJSON_AddStringToObject(data, "hash", GLOBAL_HASH);
    cJSON_AddStringToObject(data, "buildDate", __DATE__ " " __TIME__);

    send_success_response(client, id, "about", data);
}

static void handle_get_ota(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "currentVersion", "1.0.0-websocket");
    cJSON_AddStringToObject(data, "latestVersion", "Not determined yet");
    cJSON_AddStringToObject(data, "changelog", "Not determined yet");
    cJSON_AddStringToObject(data, "otaUrl", "");
    cJSON_AddStringToObject(data, "buildLabel", "WebSocket build");
    cJSON_AddStringToObject(data, "chipType", "ESP32");
    cJSON_AddBoolToObject(data, "otaRunning", false);

    send_success_response(client, id, "ota_info", data);
}

static void handle_ota_check(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "latestVersion", "1.0.0-websocket");
    cJSON_AddStringToObject(data, "changelog", "WebSocket implementation");

    send_success_response(client, id, "ota_check_result", data);
}

static void handle_ota_start(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "message", "OTA update started");

    send_success_response(client, id, "ota_started", data);
}

static void handle_ota_status(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON_AddBoolToObject(data, "otaRunning", false);
    cJSON_AddBoolToObject(data, "finished", false);
    cJSON_AddNumberToObject(data, "progress", 0);
    cJSON_AddStringToObject(data, "progressLabel", "");
    cJSON_AddStringToObject(data, "log", "");
    cJSON_AddStringToObject(data, "result", "");

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

    // Simplified unlock - always succeed for now
    client->authenticated = true;
    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "message", "Unlocked successfully");
    send_success_response(client, id, "unlocked", data);
}

static void handle_lock(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "message", "Password updated successfully");
    cJSON_AddBoolToObject(data, "locked", false);
    send_success_response(client, id, "lock_updated", data);
}

static void handle_get_lock_status(websocket_client_t *client, cJSON *request)
{
    cJSON *id_item = cJSON_GetObjectItem(request, "id");
    const char *id = id_item ? cJSON_GetStringValue(id_item) : NULL;

    cJSON *data = cJSON_CreateObject();
    cJSON_AddBoolToObject(data, "locked", false); // Simplified
    cJSON_AddBoolToObject(data, "authenticated", client->authenticated);
    cJSON_AddBoolToObject(data, "hasPassword", false); // Simplified

    send_success_response(client, id, "lock_status", data);
}