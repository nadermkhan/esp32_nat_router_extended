#include "handler.h"
#include "esp_wifi_ap_get_sta_list.h"
#include "nvs.h"
#include "esp_mac.h"
#include "lwip/netif.h"
#include "dhcpserver/dhcpserver.h"

static const char *TAG = "ClientsHandler";

// Blocked clients storage with persistence
#define MAX_BLOCKED_CLIENTS 50
#define BLOCKED_CLIENTS_NVS_KEY "blocked_clients"
#define CLIENT_TIMEOUT_SECONDS 300 // 5 minutes

typedef struct {
    uint8_t mac[6];
    uint32_t blocked_time;
    char reason[64];
    bool permanent;
} blocked_client_t;

typedef struct {
    uint8_t mac[6];
    esp_ip4_addr_t ip;
    int8_t rssi;
    uint32_t last_seen;
    uint32_t connect_time;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    bool is_blocked;
} client_info_t;

static blocked_client_t blocked_clients[MAX_BLOCKED_CLIENTS];
static int blocked_count = 0;
static bool blocked_list_loaded = false;

// Load blocked clients from NVS
static esp_err_t load_blocked_clients(void) {
    if (blocked_list_loaded) {
        return ESP_OK;
    }

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to open NVS for reading blocked clients");
        blocked_list_loaded = true;
        return err;
    }

    size_t required_size = sizeof(blocked_clients);
    err = nvs_get_blob(nvs_handle, BLOCKED_CLIENTS_NVS_KEY, blocked_clients, &required_size);
    if (err == ESP_OK) {
        blocked_count = required_size / sizeof(blocked_client_t);
        ESP_LOGI(TAG, "Loaded %d blocked clients from NVS", blocked_count);
    } else if (err == ESP_ERR_NVS_NOT_FOUND) {
        blocked_count = 0;
        ESP_LOGI(TAG, "No blocked clients found in NVS");
    } else {
        ESP_LOGW(TAG, "Failed to load blocked clients: %s", esp_err_to_name(err));
    }

    nvs_close(nvs_handle);
    blocked_list_loaded = true;
    return ESP_OK;
}

// Save blocked clients to NVS
static esp_err_t save_blocked_clients(void) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for writing blocked clients");
        return err;
    }

    if (blocked_count > 0) {
        err = nvs_set_blob(nvs_handle, BLOCKED_CLIENTS_NVS_KEY, blocked_clients, 
                          blocked_count * sizeof(blocked_client_t));
    } else {
        err = nvs_erase_key(nvs_handle, BLOCKED_CLIENTS_NVS_KEY);
    }

    if (err == ESP_OK) {
        err = nvs_commit(nvs_handle);
    }

    nvs_close(nvs_handle);
    return err;
}

// Check if client is blocked
static bool is_client_blocked(uint8_t *mac) {
    load_blocked_clients();
    
    uint32_t current_time = esp_timer_get_time() / 1000000; // seconds
    
    for (int i = 0; i < blocked_count; i++) {
        if (memcmp(blocked_clients[i].mac, mac, 6) == 0) {
            // Check if temporary block has expired
            if (!blocked_clients[i].permanent && 
                (current_time - blocked_clients[i].blocked_time) > CLIENT_TIMEOUT_SECONDS) {
                // Remove expired block
                memmove(&blocked_clients[i], &blocked_clients[i + 1], 
                       (blocked_count - i - 1) * sizeof(blocked_client_t));
                blocked_count--;
                save_blocked_clients();
                return false;
            }
            return true;
        }
    }
    return false;
}

// Parse MAC address from string
static bool parse_mac_address(const char *mac_str, uint8_t *mac) {
    if (!mac_str || !mac) {
        return false;
    }
    
    int values[6];
    int count = sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                      &values[0], &values[1], &values[2], 
                      &values[3], &values[4], &values[5]);
    
    if (count != 6) {
        return false;
    }
    
    for (int i = 0; i < 6; i++) {
        if (values[i] < 0 || values[i] > 255) {
            return false;
        }
        mac[i] = (uint8_t)values[i];
    }
    
    return true;
}

// Format MAC address to string
static void format_mac_address(uint8_t *mac, char *mac_str, size_t size) {
    snprintf(mac_str, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Get detailed client information
static esp_err_t get_client_details(client_info_t *clients, int *client_count) {
    wifi_sta_list_t wifi_sta_list;
    wifi_sta_mac_ip_list_t adapter_sta_list;
    
    memset(&wifi_sta_list, 0, sizeof(wifi_sta_list));
    memset(&adapter_sta_list, 0, sizeof(adapter_sta_list));
    
    esp_err_t ret = esp_wifi_ap_get_sta_list(&wifi_sta_list);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get STA list: %s", esp_err_to_name(ret));
        return ret;
    }
    
    ret = esp_wifi_ap_get_sta_list_with_ip(&wifi_sta_list, &adapter_sta_list);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get STA list with IP: %s", esp_err_to_name(ret));
        return ret;
    }
    
    *client_count = adapter_sta_list.num;
    uint32_t current_time = esp_timer_get_time() / 1000000;
    
    for (int i = 0; i < adapter_sta_list.num && i < MAX_BLOCKED_CLIENTS; i++) {
        esp_netif_pair_mac_ip_t *station = &adapter_sta_list.sta[i];
        
        memcpy(clients[i].mac, station->mac, 6);
        clients[i].ip = station->ip;
        clients[i].last_seen = current_time;
        clients[i].connect_time = current_time; // Simplified - would need tracking
        clients[i].is_blocked = is_client_blocked(station->mac);
        
        // Get RSSI for this client (simplified)
        clients[i].rssi = -50; // Default value, would need actual implementation
        
        // Traffic stats would need actual implementation
        clients[i].rx_bytes = 0;
        clients[i].tx_bytes = 0;
    }
    
    return ESP_OK;
}

esp_err_t api_clients_get_handler(httpd_req_t *req) {
    if (isLocked()) {
        api_response_t response = {
            .success = false,
            .message = "System locked",
            .status_code = 401
        };
        return send_api_response(req, &response);
    }

    if (!check_rate_limit(req)) {
        api_response_t response = {
            .success = false,
            .message = "Rate limit exceeded",
            .status_code = 429
        };
        return send_api_response(req, &response);
    }

    client_info_t clients[MAX_BLOCKED_CLIENTS];
    int client_count = 0;
    
    esp_err_t ret = get_client_details(clients, &client_count);
    if (ret != ESP_OK) {
        api_response_t response = {
            .success = false,
            .message = "Failed to retrieve client information",
            .status_code = 500
        };
        return send_api_response(req, &response);
    }

    cJSON *data = cJSON_CreateObject();
    cJSON *clients_array = cJSON_CreateArray();
    cJSON *blocked_array = cJSON_CreateArray();

    // Add connected clients
    for (int i = 0; i < client_count; i++) {
        cJSON *client = cJSON_CreateObject();
        
        char mac_str[18];
        format_mac_address(clients[i].mac, mac_str, sizeof(mac_str));
        
        char ip_str[16];
        esp_ip4addr_ntoa(&clients[i].ip, ip_str, sizeof(ip_str));
        
        cJSON_AddNumberToObject(client, "id", i + 1);
        cJSON_AddStringToObject(client, "mac", mac_str);
        cJSON_AddStringToObject(client, "ip", ip_str);
        cJSON_AddNumberToObject(client, "rssi", clients[i].rssi);
        cJSON_AddNumberToObject(client, "lastSeen", clients[i].last_seen);
        cJSON_AddNumberToObject(client, "connectTime", clients[i].connect_time);
        cJSON_AddNumberToObject(client, "rxBytes", clients[i].rx_bytes);
        cJSON_AddNumberToObject(client, "txBytes", clients[i].tx_bytes);
        cJSON_AddBoolToObject(client, "isBlocked", clients[i].is_blocked);
        
        // Signal strength category
        const char *signal_strength = "poor";
        if (clients[i].rssi >= -50) signal_strength = "excellent";
        else if (clients[i].rssi >= -60) signal_strength = "good";
        else if (clients[i].rssi >= -70) signal_strength = "fair";
        
        cJSON_AddStringToObject(client, "signalStrength", signal_strength);
        
        cJSON_AddItemToArray(clients_array, client);
    }

    // Add blocked clients list
    load_blocked_clients();
    for (int i = 0; i < blocked_count; i++) {
        cJSON *blocked = cJSON_CreateObject();
        
        char mac_str[18];
        format_mac_address(blocked_clients[i].mac, mac_str, sizeof(mac_str));
        
        cJSON_AddStringToObject(blocked, "mac", mac_str);
        cJSON_AddNumberToObject(blocked, "blockedTime", blocked_clients[i].blocked_time);
        cJSON_AddStringToObject(blocked, "reason", blocked_clients[i].reason);
        cJSON_AddBoolToObject(blocked, "permanent", blocked_clients[i].permanent);
        
        cJSON_AddItemToArray(blocked_array, blocked);
    }

    cJSON_AddItemToObject(data, "connected", clients_array);
    cJSON_AddItemToObject(data, "blocked", blocked_array);
    cJSON_AddNumberToObject(data, "connectedCount", client_count);
    cJSON_AddNumberToObject(data, "blockedCount", blocked_count);
    cJSON_AddNumberToObject(data, "maxClients", CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM);

    // Add network statistics
    cJSON *stats = cJSON_CreateObject();
    cJSON_AddNumberToObject(stats, "totalConnections", client_count);
    cJSON_AddNumberToObject(stats, "activeConnections", client_count);
    cJSON_AddItemToObject(data, "statistics", stats);

    api_response_t response = {
        .success = true,
        .message = "Client information retrieved successfully",
        .data = data,
        .status_code = 200
    };

    ESP_LOGI(TAG, "Retrieved information for %d clients", client_count);
    return send_api_response(req, &response);
}

esp_err_t api_clients_block_post_handler(httpd_req_t *req) {
    if (isLocked()) {
        api_response_t response = {
            .success = false,
            .message = "System locked",
            .status_code = 401
        };
        return send_api_response(req, &response);
    }

    if (!validate_request_size(req)) {
        api_response_t response = {
            .success = false,
            .message = "Request too large",
            .status_code = 413
        };
        return send_api_response(req, &response);
    }

    char buf[req->content_len + 1];
    if (fill_post_buffer(req, buf, req->content_len) != ESP_OK) {
        api_response_t response = {
            .success = false,
            .message = "Failed to read request data",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }
    buf[req->content_len] = '\0';

    char mac_param[32] = {0};
    char reason_param[64] = {0};
    char permanent_param[8] = {0};

    readUrlParameterIntoBuffer(buf, "mac", mac_param, sizeof(mac_param));
    readUrlParameterIntoBuffer(buf, "reason", reason_param, sizeof(reason_param));
    readUrlParameterIntoBuffer(buf, "permanent", permanent_param, sizeof(permanent_param));

    if (strlen(mac_param) == 0) {
        api_response_t response = {
            .success = false,
            .message = "MAC address is required",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }

    sanitize_string_input(mac_param, sizeof(mac_param));
    sanitize_string_input(reason_param, sizeof(reason_param));

    uint8_t mac[6];
    if (!parse_mac_address(mac_param, mac)) {
        api_response_t response = {
            .success = false,
            .message = "Invalid MAC address format",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }

    load_blocked_clients();

    // Check if already blocked
    if (is_client_blocked(mac)) {
        api_response_t response = {
            .success = false,
            .message = "Client is already blocked",
            .status_code = 409
        };
        return send_api_response(req, &response);
    }

    // Check capacity
    if (blocked_count >= MAX_BLOCKED_CLIENTS) {
        api_response_t response = {
            .success = false,
            .message = "Maximum number of blocked clients reached",
            .status_code = 507
        };
        return send_api_response(req, &response);
    }

        // Add to blocked list
    memcpy(blocked_clients[blocked_count].mac, mac, 6);
    blocked_clients[blocked_count].blocked_time = esp_timer_get_time() / 1000000;
    blocked_clients[blocked_count].permanent = (strcmp(permanent_param, "true") == 0);
    
    if (strlen(reason_param) > 0) {
        strncpy(blocked_clients[blocked_count].reason, reason_param, sizeof(blocked_clients[blocked_count].reason) - 1);
        blocked_clients[blocked_count].reason[sizeof(blocked_clients[blocked_count].reason) - 1] = '\0';
    } else {
        strcpy(blocked_clients[blocked_count].reason, "Manual block");
    }
    
    blocked_count++;

    // Save to NVS
    esp_err_t save_result = save_blocked_clients();
    if (save_result != ESP_OK) {
        ESP_LOGW(TAG, "Failed to save blocked clients to NVS: %s", esp_err_to_name(save_result));
    }

    // Disconnect the client if currently connected
    wifi_sta_list_t sta_list;
    memset(&sta_list, 0, sizeof(sta_list));
    esp_err_t ret = esp_wifi_ap_get_sta_list(&sta_list);
    
    if (ret == ESP_OK) {
        for (int i = 0; i < sta_list.num; i++) {
            if (memcmp(sta_list.sta[i].mac, mac, 6) == 0) {
                esp_err_t deauth_ret = esp_wifi_deauth_sta(sta_list.sta[i].aid);
                if (deauth_ret != ESP_OK) {
                    ESP_LOGW(TAG, "Failed to deauth client: %s", esp_err_to_name(deauth_ret));
                }
                break;
            }
        }
    }

    char mac_str[18];
    format_mac_address(mac, mac_str, sizeof(mac_str));

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "blockedMac", mac_str);
    cJSON_AddStringToObject(data, "reason", blocked_clients[blocked_count - 1].reason);
    cJSON_AddBoolToObject(data, "permanent", blocked_clients[blocked_count - 1].permanent);
    cJSON_AddNumberToObject(data, "totalBlocked", blocked_count);

    api_response_t response = {
        .success = true,
        .message = "Client blocked successfully",
        .data = data,
        .status_code = 200
    };

    ESP_LOGI(TAG, "Blocked client %s, reason: %s, permanent: %s", 
             mac_str, blocked_clients[blocked_count - 1].reason,
             blocked_clients[blocked_count - 1].permanent ? "yes" : "no");

    return send_api_response(req, &response);
}

esp_err_t api_clients_unblock_post_handler(httpd_req_t *req) {
    if (isLocked()) {
        api_response_t response = {
            .success = false,
            .message = "System locked",
            .status_code = 401
        };
        return send_api_response(req, &response);
    }

    if (!validate_request_size(req)) {
        api_response_t response = {
            .success = false,
            .message = "Request too large",
            .status_code = 413
        };
        return send_api_response(req, &response);
    }

    char buf[req->content_len + 1];
    if (fill_post_buffer(req, buf, req->content_len) != ESP_OK) {
        api_response_t response = {
            .success = false,
            .message = "Failed to read request data",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }
    buf[req->content_len] = '\0';

    char mac_param[32] = {0};
    readUrlParameterIntoBuffer(buf, "mac", mac_param, sizeof(mac_param));

    if (strlen(mac_param) == 0) {
        api_response_t response = {
            .success = false,
            .message = "MAC address is required",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }

    sanitize_string_input(mac_param, sizeof(mac_param));

    uint8_t mac[6];
    if (!parse_mac_address(mac_param, mac)) {
        api_response_t response = {
            .success = false,
            .message = "Invalid MAC address format",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }

    load_blocked_clients();

    // Find and remove from blocked list
    bool found = false;
    for (int i = 0; i < blocked_count; i++) {
        if (memcmp(blocked_clients[i].mac, mac, 6) == 0) {
            // Remove by shifting remaining elements
            memmove(&blocked_clients[i], &blocked_clients[i + 1], 
                   (blocked_count - i - 1) * sizeof(blocked_client_t));
            blocked_count--;
            found = true;
            break;
        }
    }

    if (!found) {
        api_response_t response = {
            .success = false,
            .message = "Client is not in blocked list",
            .status_code = 404
        };
        return send_api_response(req, &response);
    }

    // Save to NVS
    esp_err_t save_result = save_blocked_clients();
    if (save_result != ESP_OK) {
        ESP_LOGW(TAG, "Failed to save blocked clients to NVS: %s", esp_err_to_name(save_result));
    }

    char mac_str[18];
    format_mac_address(mac, mac_str, sizeof(mac_str));

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "unblockedMac", mac_str);
    cJSON_AddNumberToObject(data, "totalBlocked", blocked_count);

    api_response_t response = {
        .success = true,
        .message = "Client unblocked successfully",
        .data = data,
        .status_code = 200
    };

    ESP_LOGI(TAG, "Unblocked client %s", mac_str);
    return send_api_response(req, &response);
}

// Cleanup function to remove expired temporary blocks
void cleanup_expired_blocks(void) {
    load_blocked_clients();
    
    uint32_t current_time = esp_timer_get_time() / 1000000;
    bool changed = false;
    
    for (int i = blocked_count - 1; i >= 0; i--) {
        if (!blocked_clients[i].permanent && 
            (current_time - blocked_clients[i].blocked_time) > CLIENT_TIMEOUT_SECONDS) {
            
            char mac_str[18];
            format_mac_address(blocked_clients[i].mac, mac_str, sizeof(mac_str));
            ESP_LOGI(TAG, "Removing expired block for client %s", mac_str);
            
            memmove(&blocked_clients[i], &blocked_clients[i + 1], 
                   (blocked_count - i - 1) * sizeof(blocked_client_t));
            blocked_count--;
            changed = true;
        }
    }
    
    if (changed) {
        save_blocked_clients();
    }
}

// Function to check if a connecting client should be blocked
bool should_block_client(uint8_t *mac) {
    return is_client_blocked(mac);
}