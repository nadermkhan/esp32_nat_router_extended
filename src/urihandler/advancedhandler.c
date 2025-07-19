#include "handler.h"
#include "dhcpserver/dhcpserver.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_netif.h"

static const char *TAG = "AdvancedHandler";

// Validation functions
static bool validate_hostname(const char *hostname) {
    if (!hostname || strlen(hostname) == 0 || strlen(hostname) > 63) {
        return false;
    }
    
    // Check valid characters (alphanumeric and hyphens, not starting/ending with hyphen)
    if (hostname[0] == '-' || hostname[strlen(hostname) - 1] == '-') {
        return false;
    }
    
    for (size_t i = 0; i < strlen(hostname); i++) {
        char c = hostname[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || c == '-')) {
            return false;
        }
    }
    return true;
}

static bool validate_tx_power(int power) {
    return power >= 8 && power <= 84; // ESP32 valid range
}

static bool validate_octet(int octet) {
    return octet >= 1 && octet <= 254; // Valid IP octet range (excluding network/broadcast)
}

esp_err_t api_advanced_get_handler(httpd_req_t *req) {
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

    cJSON *data = cJSON_CreateObject();

    // Get configuration values with error handling
    int32_t keepAlive = 0, ledDisabled = 0, natDisabled = 0;
    int32_t octet = 4, txPower = 80, bandwidth = 0;
    char *hostName = NULL;

    esp_err_t err;
    err = get_config_param_int("keep_alive", &keepAlive);
    if (err != ESP_OK) keepAlive = 0;
    
    err = get_config_param_int("led_disabled", &ledDisabled);
    if (err != ESP_OK) ledDisabled = 0;
    
    err = get_config_param_int("nat_disabled", &natDisabled);
    if (err != ESP_OK) natDisabled = 0;
    
    err = get_config_param_str("hostname", &hostName);
    if (err != ESP_OK || !hostName) hostName = strdup("");
    
    err = get_config_param_int("octet", &octet);
    if (err != ESP_OK) octet = 4;
    
    err = get_config_param_int("txpower", &txPower);
    if (err != ESP_OK) txPower = 80;
    
    err = get_config_param_int("lower_bandwidth", &bandwidth);
    if (err != ESP_OK) bandwidth = 0;

    // Basic settings
    cJSON *basic = cJSON_CreateObject();
    cJSON_AddBoolToObject(basic, "keepAlive", keepAlive == 1);
    cJSON_AddBoolToObject(basic, "ledEnabled", ledDisabled == 0);
    cJSON_AddBoolToObject(basic, "natEnabled", natDisabled == 0);
    cJSON_AddStringToObject(basic, "hostname", hostName ? hostName : "");
    cJSON_AddNumberToObject(basic, "octet", octet);
    cJSON_AddBoolToObject(basic, "lowerBandwidth", bandwidth == 1);
    cJSON_AddItemToObject(data, "basic", basic);

    // WiFi settings
    cJSON *wifi = cJSON_CreateObject();
    
    // TX Power with validation
    const char *txPowerLevel = "high";
    if (txPower < 34) txPowerLevel = "low";
    else if (txPower < 60) txPowerLevel = "medium";
    
    cJSON_AddStringToObject(wifi, "txPowerLevel", txPowerLevel);
    cJSON_AddNumberToObject(wifi, "txPowerValue", txPower);
    
    // Get current WiFi channel and country
    wifi_config_t wifi_config;
    if (esp_wifi_get_config(WIFI_IF_AP, &wifi_config) == ESP_OK) {
        cJSON_AddNumberToObject(wifi, "channel", wifi_config.ap.channel);
        cJSON_AddNumberToObject(wifi, "maxConnections", wifi_config.ap.max_connection);
    }
    
    wifi_country_t country;
    if (esp_wifi_get_country(&country) == ESP_OK) {
        char country_str[4] = {0};
        memcpy(country_str, country.cc, 2);
        cJSON_AddStringToObject(wifi, "country", country_str);
        cJSON_AddNumberToObject(wifi, "startChannel", country.schan);
        cJSON_AddNumberToObject(wifi, "totalChannels", country.nchan);
    }
    
    cJSON_AddItemToObject(data, "wifi", wifi);

    // DNS settings with current resolution
    cJSON *dns = cJSON_CreateObject();
    esp_netif_dns_info_t dns_info;
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    
    char currentDNS[16] = "Not available";
    if (netif && esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns_info) == ESP_OK) {
        esp_ip4addr_ntoa(&dns_info.ip.u_addr.ip4, currentDNS, sizeof(currentDNS));
    }
    cJSON_AddStringToObject(dns, "current", currentDNS);

    char *customDNS = NULL;
    get_config_param_str("custom_dns", &customDNS);
    
    const char *dnsType = "default";
    if (customDNS != NULL) {
        if (strcmp(customDNS, "1.1.1.1") == 0) dnsType = "cloudflare";
        else if (strcmp(customDNS, "8.8.8.8") == 0) dnsType = "google";
        else if (strcmp(customDNS, "94.140.14.14") == 0) dnsType = "adguard";
        else if (strcmp(customDNS, "208.67.222.222") == 0) dnsType = "opendns";
        else dnsType = "custom";
    }
    
    cJSON_AddStringToObject(dns, "type", dnsType);
    cJSON_AddStringToObject(dns, "customIP", customDNS ? customDNS : "");
    cJSON_AddItemToObject(data, "dns", dns);

    // MAC settings with validation
    cJSON *mac_settings = cJSON_CreateObject();
    uint8_t base_mac[6] = {0};
    uint8_t default_mac[6] = {0};
    
    char currentMAC[18] = "Unknown";
    char defaultMAC[18] = "Unknown";
    
    if (esp_base_mac_addr_get(base_mac) == ESP_OK) {
        format_mac_address(base_mac, currentMAC, sizeof(currentMAC));
    }
    
        if (esp_efuse_mac_get_default(default_mac) == ESP_OK) {
        format_mac_address(default_mac, defaultMAC, sizeof(defaultMAC));
    }

    cJSON_AddStringToObject(mac_settings, "current", currentMAC);
    cJSON_AddStringToObject(mac_settings, "default", defaultMAC);

    char *macSetting = NULL;
    get_config_param_str("custom_mac", &macSetting);
    
    const char *macType = "default";
    if (macSetting && strcmp(macSetting, "random") == 0) {
        macType = "random";
    } else if (strcmp(currentMAC, defaultMAC) != 0) {
        macType = "custom";
    }
    cJSON_AddStringToObject(mac_settings, "type", macType);
    cJSON_AddItemToObject(data, "mac", mac_settings);

    // Network settings
    cJSON *network = cJSON_CreateObject();
    char *netmask = getNetmask();
    cJSON_AddStringToObject(network, "netmask", netmask);
    
    const char *netmaskType = "classc";
    if (strcmp(netmask, DEFAULT_NETMASK_CLASS_A) == 0) netmaskType = "classa";
    else if (strcmp(netmask, DEFAULT_NETMASK_CLASS_B) == 0) netmaskType = "classb";
    else if (strcmp(netmask, DEFAULT_NETMASK_CLASS_C) != 0) netmaskType = "custom";
    
    cJSON_AddStringToObject(network, "netmaskType", netmaskType);
    
    // Add IP range information
    char *defaultIP = getDefaultIPByNetmask();
    cJSON_AddStringToObject(network, "gatewayIP", defaultIP);
    
    // Calculate network range
    uint32_t ip_addr = esp_ip4addr_aton(defaultIP);
    uint32_t mask_addr = esp_ip4addr_aton(netmask);
    uint32_t network_addr = ip_addr & mask_addr;
    uint32_t broadcast_addr = network_addr | (~mask_addr);
    
    esp_ip4_addr_t net_ip, broadcast_ip;
    net_ip.addr = network_addr;
    broadcast_ip.addr = broadcast_addr;
    
    char network_str[16], broadcast_str[16];
    esp_ip4addr_ntoa(&net_ip, network_str, sizeof(network_str));
    esp_ip4addr_ntoa(&broadcast_ip, broadcast_str, sizeof(broadcast_str));
    
    cJSON_AddStringToObject(network, "networkAddress", network_str);
    cJSON_AddStringToObject(network, "broadcastAddress", broadcast_str);
    
    // Calculate available host addresses
    uint32_t host_bits = 32 - __builtin_popcount(mask_addr);
    uint32_t max_hosts = (1 << host_bits) - 2; // Subtract network and broadcast
    cJSON_AddNumberToObject(network, "maxHosts", max_hosts);
    
    free(defaultIP);
    cJSON_AddItemToObject(data, "network", network);

    // Security settings
    cJSON *security = cJSON_CreateObject();
    
    // Check if firewall/blocking is enabled
    cJSON_AddBoolToObject(security, "clientBlockingEnabled", true);
    cJSON_AddNumberToObject(security, "maxBlockedClients", MAX_BLOCKED_CLIENTS);
    
    // Rate limiting info
    cJSON_AddNumberToObject(security, "rateLimitWindow", API_RATE_LIMIT_WINDOW / 1000);
    cJSON_AddNumberToObject(security, "rateLimitMaxRequests", API_RATE_LIMIT_MAX_REQUESTS);
    
    cJSON_AddItemToObject(data, "security", security);

    // Performance settings
    cJSON *performance = cJSON_CreateObject();
    
    // Get current CPU frequency
    rtc_cpu_freq_config_t freq_config;
    rtc_clk_cpu_freq_get_config(&freq_config);
    cJSON_AddNumberToObject(performance, "cpuFreqMHz", freq_config.freq_mhz);
    
    // WiFi performance settings
    wifi_ps_type_t ps_type;
    if (esp_wifi_get_ps(&ps_type) == ESP_OK) {
        const char *power_save = "none";
        switch (ps_type) {
            case WIFI_PS_MIN_MODEM: power_save = "minimum"; break;
            case WIFI_PS_MAX_MODEM: power_save = "maximum"; break;
            default: power_save = "none"; break;
        }
        cJSON_AddStringToObject(performance, "wifiPowerSave", power_save);
    }
    
    cJSON_AddItemToObject(data, "performance", performance);

    // Cleanup
    if (hostName) free(hostName);
    if (customDNS) free(customDNS);
    if (macSetting) free(macSetting);

    api_response_t response = {
        .success = true,
        .message = "Advanced configuration retrieved successfully",
        .data = data,
        .status_code = 200
    };

    return send_api_response(req, &response);
}

esp_err_t api_advanced_post_handler(httpd_req_t *req) {
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

    nvs_handle_t nvs;
    esp_err_t nvs_err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (nvs_err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(nvs_err));
        api_response_t response = {
            .success = false,
            .message = "Configuration storage error",
            .status_code = 500
        };
        return send_api_response(req, &response);
    }

    cJSON *changes = cJSON_CreateArray();
    bool restart_required = false;

    // Process each configuration parameter with validation
    char param[MAX_PARAM_LENGTH];

    // Keep alive setting
    readUrlParameterIntoBuffer(buf, "keepalive", param, sizeof(param));
    bool keepalive = (strlen(param) > 0 && strcmp(param, "true") == 0);
    nvs_set_i32(nvs, "keep_alive", keepalive ? 1 : 0);
    cJSON *change = cJSON_CreateObject();
    cJSON_AddStringToObject(change, "setting", "keepAlive");
    cJSON_AddBoolToObject(change, "value", keepalive);
    cJSON_AddItemToArray(changes, change);

    // LED setting
    readUrlParameterIntoBuffer(buf, "ledenabled", param, sizeof(param));
    bool led_enabled = (strlen(param) > 0 && strcmp(param, "true") == 0);
    nvs_set_i32(nvs, "led_disabled", led_enabled ? 0 : 1);
    change = cJSON_CreateObject();
    cJSON_AddStringToObject(change, "setting", "ledEnabled");
    cJSON_AddBoolToObject(change, "value", led_enabled);
    cJSON_AddItemToArray(changes, change);

    // NAT setting
    readUrlParameterIntoBuffer(buf, "natenabled", param, sizeof(param));
    bool nat_enabled = (strlen(param) > 0 && strcmp(param, "true") == 0);
    nvs_set_i32(nvs, "nat_disabled", nat_enabled ? 0 : 1);
    change = cJSON_CreateObject();
    cJSON_AddStringToObject(change, "setting", "natEnabled");
    cJSON_AddBoolToObject(change, "value", nat_enabled);
    cJSON_AddItemToArray(changes, change);
    if (!nat_enabled) restart_required = true;

    // Hostname setting with validation
    readUrlParameterIntoBuffer(buf, "hostname", param, sizeof(param));
    sanitize_string_input(param, sizeof(param));
    if (strlen(param) > 0) {
        if (validate_hostname(param)) {
            nvs_set_str(nvs, "hostname", param);
            change = cJSON_CreateObject();
            cJSON_AddStringToObject(change, "setting", "hostname");
            cJSON_AddStringToObject(change, "value", param);
            cJSON_AddItemToArray(changes, change);
            restart_required = true;
        } else {
            nvs_close(nvs);
            cJSON_Delete(changes);
            api_response_t response = {
                .success = false,
                .message = "Invalid hostname format",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }
    } else {
        nvs_erase_key(nvs, "hostname");
        change = cJSON_CreateObject();
        cJSON_AddStringToObject(change, "setting", "hostname");
        cJSON_AddStringToObject(change, "value", "");
        cJSON_AddItemToArray(changes, change);
    }

    // Octet setting with validation
    readUrlParameterIntoBuffer(buf, "octet", param, sizeof(param));
    if (strlen(param) > 0) {
        int octet = atoi(param);
        if (validate_octet(octet)) {
            nvs_set_i32(nvs, "octet", octet);
            change = cJSON_CreateObject();
            cJSON_AddStringToObject(change, "setting", "octet");
            cJSON_AddNumberToObject(change, "value", octet);
            cJSON_AddItemToArray(changes, change);
            restart_required = true;
        } else {
            nvs_close(nvs);
            cJSON_Delete(changes);
            api_response_t response = {
                .success = false,
                .message = "Invalid octet value (must be 1-254)",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }
    }

    // TX Power setting with validation
    readUrlParameterIntoBuffer(buf, "txpower", param, sizeof(param));
    if (strlen(param) > 0) {
        int tx_power = atoi(param);
        if (validate_tx_power(tx_power)) {
            nvs_set_i32(nvs, "txpower", tx_power);
            change = cJSON_CreateObject();
            cJSON_AddStringToObject(change, "setting", "txPower");
            cJSON_AddNumberToObject(change, "value", tx_power);
            cJSON_AddItemToArray(changes, change);
            
            // Apply immediately if possible
            esp_err_t power_err = esp_wifi_set_max_tx_power(tx_power);
            if (power_err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to set TX power immediately: %s", esp_err_to_name(power_err));
            }
        } else {
            nvs_close(nvs);
            cJSON_Delete(changes);
            api_response_t response = {
                .success = false,
                .message = "Invalid TX power value (must be 8-84)",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }
    }

    // Bandwidth setting
    readUrlParameterIntoBuffer(buf, "bandwidth", param, sizeof(param));
    bool lower_bandwidth = (strlen(param) > 0 && strcmp(param, "true") == 0);
    if (lower_bandwidth) {
        nvs_set_i32(nvs, "lower_bandwidth", 1);
    } else {
        nvs_erase_key(nvs, "lower_bandwidth");
    }
    change = cJSON_CreateObject();
    cJSON_AddStringToObject(change, "setting", "lowerBandwidth");
    cJSON_AddBoolToObject(change, "value", lower_bandwidth);
    cJSON_AddItemToArray(changes, change);

    // DNS setting with validation
    readUrlParameterIntoBuffer(buf, "dns", param, sizeof(param));
    if (strlen(param) > 0) {
        if (strcmp(param, "custom") == 0) {
            char custom_dns[32];
            readUrlParameterIntoBuffer(buf, "dnsip", custom_dns, sizeof(custom_dns));
            sanitize_string_input(custom_dns, sizeof(custom_dns));
            
            if (strlen(custom_dns) > 0 && is_valid_ip_address(custom_dns)) {
                nvs_set_str(nvs, "custom_dns", custom_dns);
                change = cJSON_CreateObject();
                cJSON_AddStringToObject(change, "setting", "customDNS");
                cJSON_AddStringToObject(change, "value", custom_dns);
                cJSON_AddItemToArray(changes, change);
            } else {
                nvs_close(nvs);
                cJSON_Delete(changes);
                api_response_t response = {
                    .success = false,
                    .message = "Invalid custom DNS IP address",
                    .status_code = 400
                };
                return send_api_response(req, &response);
            }
        } else {
            // Predefined DNS servers
            const char *dns_ip = NULL;
            if (strcmp(param, "cloudflare") == 0) dns_ip = "1.1.1.1";
            else if (strcmp(param, "google") == 0) dns_ip = "8.8.8.8";
            else if (strcmp(param, "adguard") == 0) dns_ip = "94.140.14.14";
            else if (strcmp(param, "opendns") == 0) dns_ip = "208.67.222.222";
            
            if (dns_ip) {
                nvs_set_str(nvs, "custom_dns", dns_ip);
                change = cJSON_CreateObject();
                cJSON_AddStringToObject(change, "setting", "dnsType");
                cJSON_AddStringToObject(change, "value", param);
                cJSON_AddItemToArray(changes, change);
            }
        }
    } else {
        nvs_erase_key(nvs, "custom_dns");
        change = cJSON_CreateObject();
        cJSON_AddStringToObject(change, "setting", "dnsType");
        cJSON_AddStringToObject(change, "value", "default");
        cJSON_AddItemToArray(changes, change);
    }

    // MAC address setting with validation
    readUrlParameterIntoBuffer(buf, "custommac", param, sizeof(param));
    if (strlen(param) > 0) {
        if (strcmp(param, "random") == 0) {
                        nvs_set_str(nvs, "custom_mac", "random");
            change = cJSON_CreateObject();
            cJSON_AddStringToObject(change, "setting", "macType");
            cJSON_AddStringToObject(change, "value", "random");
            cJSON_AddItemToArray(changes, change);
            restart_required = true;
        } else if (strcmp(param, "custom") == 0) {
            char mac_address[32];
            readUrlParameterIntoBuffer(buf, "macaddress", mac_address, sizeof(mac_address));
            sanitize_string_input(mac_address, sizeof(mac_address));
            
            uint8_t mac[6];
            if (strlen(mac_address) > 0 && parse_mac_address(mac_address, mac)) {
                nvs_set_str(nvs, "custom_mac", mac_address);
                change = cJSON_CreateObject();
                cJSON_AddStringToObject(change, "setting", "customMAC");
                cJSON_AddStringToObject(change, "value", mac_address);
                cJSON_AddItemToArray(changes, change);
                restart_required = true;
            } else {
                nvs_close(nvs);
                cJSON_Delete(changes);
                api_response_t response = {
                    .success = false,
                    .message = "Invalid MAC address format",
                    .status_code = 400
                };
                return send_api_response(req, &response);
            }
        } else {
            nvs_erase_key(nvs, "custom_mac");
            change = cJSON_CreateObject();
            cJSON_AddStringToObject(change, "setting", "macType");
            cJSON_AddStringToObject(change, "value", "default");
            cJSON_AddItemToArray(changes, change);
            restart_required = true;
        }
    }

    // Netmask setting with validation
    readUrlParameterIntoBuffer(buf, "netmask", param, sizeof(param));
    if (strlen(param) > 0) {
        const char *netmask_value = NULL;
        
        if (strcmp(param, "classa") == 0) {
            netmask_value = DEFAULT_NETMASK_CLASS_A;
        } else if (strcmp(param, "classb") == 0) {
            netmask_value = DEFAULT_NETMASK_CLASS_B;
        } else if (strcmp(param, "classc") == 0) {
            netmask_value = DEFAULT_NETMASK_CLASS_C;
        } else if (strcmp(param, "custom") == 0) {
            char custom_mask[32];
            readUrlParameterIntoBuffer(buf, "mask", custom_mask, sizeof(custom_mask));
            sanitize_string_input(custom_mask, sizeof(custom_mask));
            
            if (strlen(custom_mask) > 0 && is_valid_subnet_mask(custom_mask)) {
                netmask_value = custom_mask;
            } else {
                nvs_close(nvs);
                cJSON_Delete(changes);
                api_response_t response = {
                    .success = false,
                    .message = "Invalid subnet mask",
                    .status_code = 400
                };
                return send_api_response(req, &response);
            }
        }
        
        if (netmask_value) {
            nvs_set_str(nvs, "netmask", netmask_value);
            change = cJSON_CreateObject();
            cJSON_AddStringToObject(change, "setting", "netmask");
            cJSON_AddStringToObject(change, "value", netmask_value);
            cJSON_AddItemToArray(changes, change);
            restart_required = true;
        }
    }

    // Commit all changes
    esp_err_t commit_err = nvs_commit(nvs);
    nvs_close(nvs);
    
    if (commit_err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit NVS changes: %s", esp_err_to_name(commit_err));
        cJSON_Delete(changes);
        api_response_t response = {
            .success = false,
            .message = "Failed to save configuration",
            .status_code = 500
        };
        return send_api_response(req, &response);
    }

    // Prepare response
    cJSON *data = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "changes", changes);
    cJSON_AddBoolToObject(data, "restartRequired", restart_required);
    cJSON_AddNumberToObject(data, "changesCount", cJSON_GetArraySize(changes));

    const char *message = restart_required ? 
        "Advanced configuration updated successfully. Restart required for some changes to take effect." :
        "Advanced configuration updated successfully.";

    api_response_t response = {
        .success = true,
        .message = message,
        .data = data,
        .status_code = 200
    };

    ESP_LOGI(TAG, "Advanced configuration updated with %d changes, restart required: %s", 
             cJSON_GetArraySize(changes), restart_required ? "yes" : "no");

    return send_api_response(req, &response);
}