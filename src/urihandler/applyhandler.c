#include "handler.h"
#include "timer.h"
#include "nvs.h"

static const char *TAG = "ApplyHandler";

// Configuration validation functions
static bool validate_ssid(const char *ssid) {
    if (!ssid) return false;
    size_t len = strlen(ssid);
    return len > 0 && len <= 32;
}

static bool validate_password(const char *password) {
    if (!password) return true; // Open network
    size_t len = strlen(password);
    return len == 0 || (len >= 8 && len <= 64);
}

static bool validate_wpa2_identity(const char *identity) {
    if (!identity) return true;
    size_t len = strlen(identity);
    return len <= 64;
}

esp_err_t api_apply_post_handler(httpd_req_t *req) {
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

    char func_param[16] = {0};
    readUrlParameterIntoBuffer(buf, "func", func_param, sizeof(func_param));
    sanitize_string_input(func_param, sizeof(func_param));

    if (strlen(func_param) == 0) {
        api_response_t response = {
            .success = false,
            .message = "Function parameter is required",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }

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

    cJSON *data = cJSON_CreateObject();
    bool restart_required = false;
    const char *message = "Configuration applied successfully";

    if (strcmp(func_param, "config") == 0) {
        // WiFi configuration
        char ap_ssid[33] = {0}, ap_password[65] = {0};
        char sta_ssid[33] = {0}, sta_password[65] = {0};
        char ssid_hidden[8] = {0};
        
        readUrlParameterIntoBuffer(buf, "ap_ssid", ap_ssid, sizeof(ap_ssid));
        readUrlParameterIntoBuffer(buf, "ap_password", ap_password, sizeof(ap_password));
        readUrlParameterIntoBuffer(buf, "ssid", sta_ssid, sizeof(sta_ssid));
        readUrlParameterIntoBuffer(buf, "password", sta_password, sizeof(sta_password));
        readUrlParameterIntoBuffer(buf, "ssid_hidden", ssid_hidden, sizeof(ssid_hidden));

        // Sanitize inputs
        sanitize_string_input(ap_ssid, sizeof(ap_ssid));
        sanitize_string_input(ap_password, sizeof(ap_password));
        sanitize_string_input(sta_ssid, sizeof(sta_ssid));
        sanitize_string_input(sta_password, sizeof(sta_password));

        // Validate AP configuration
        if (!validate_ssid(ap_ssid)) {
            nvs_close(nvs);
            api_response_t response = {
                .success = false,
                .message = "Invalid AP SSID (must be 1-32 characters)",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        if (!validate_password(ap_password)) {
            nvs_close(nvs);
            api_response_t response = {
                .success = false,
                .message = "Invalid AP password (must be 8-64 characters or empty for open network)",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        // Validate STA configuration
        if (strlen(sta_ssid) > 0 && !validate_ssid(sta_ssid)) {
            nvs_close(nvs);
            api_response_t response = {
                .success = false,
                .message = "Invalid STA SSID (must be 1-32 characters)",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        if (strlen(sta_ssid) > 0 && !validate_password(sta_password)) {
            nvs_close(nvs);
            api_response_t response = {
                .success = false,
                .message = "Invalid STA password (must be 8-64 characters or empty)",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        // Apply AP configuration
        nvs_set_str(nvs, "ap_ssid", ap_ssid);
        if (strlen(ap_password) >= 8) {
            nvs_set_str(nvs, "ap_passwd", ap_password);
        } else {
            nvs_erase_key(nvs, "ap_passwd");
        }

        // SSID hidden setting
        if (strcmp(ssid_hidden, "true") == 0) {
            nvs_set_i32(nvs, "ssid_hidden", 1);
        } else {
            nvs_erase_key(nvs, "ssid_hidden");
        }

        // Apply STA configuration
        if (strlen(sta_ssid) > 0) {
            nvs_set_str(nvs, "ssid", sta_ssid);
            nvs_set_str(nvs, "passwd", sta_password);
        }

        // WPA2 Enterprise configuration
        char sta_identity[65] = {0}, sta_user[65] = {0};
        readUrlParameterIntoBuffer(buf, "sta_identity", sta_identity, sizeof(sta_identity));
        readUrlParameterIntoBuffer(buf, "sta_user", sta_user, sizeof(sta_user));
        sanitize_string_input(sta_identity, sizeof(sta_identity));
        sanitize_string_input(sta_user, sizeof(sta_user));

        if (!validate_wpa2_identity(sta_identity) || !validate_wpa2_identity(sta_user)) {
            nvs_close(nvs);
            api_response_t response = {
                .success = false,
                .message = "Invalid WPA2 Enterprise credentials (max 64 characters)",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        if (strlen(sta_identity) > 0) {
            nvs_set_str(nvs, "sta_identity", sta_identity);
        } else {
            nvs_erase_key(nvs, "sta_identity");
        }

        if (strlen(sta_user) > 0) {
            nvs_set_str(nvs, "sta_user", sta_user);
        } else {
            nvs_erase_key(nvs, "sta_user");
        }

        // Certificate handling (simplified - would need proper validation)
        char certificate[1024] = {0};
        readUrlParameterIntoBuffer(buf, "cer", certificate, sizeof(certificate));
        if (strlen(certificate) > 0) {
            nvs_set_blob(nvs, "cer", certificate, strlen(certificate));
        } else {
            nvs_erase_key(nvs, "cer");
        }

        cJSON_AddStringToObject(data, "configType", "wifi");
        cJSON_AddStringToObject(data, "apSSID", ap_ssid);
        cJSON_AddBoolToObject(data, "apPasswordSet", strlen(ap_password) >= 8);
        cJSON_AddStringToObject(data, "staSSID", sta_ssid);
        cJSON_AddBoolToObject(data, "staPasswordSet", strlen(sta_password) > 0);
        cJSON_AddBoolToObject(data, "wpa2Enterprise", strlen(sta_identity) > 0 || strlen(sta_user) > 0);
        
        message = "WiFi configuration applied successfully";
        restart_required = true;

    } else if (strcmp(func_param, "erase") == 0) {
        // Erase all configuration
        ESP_LOGW(TAG, "Erasing all configuration data");
        
        // Get list of all keys to erase
        nvs_iterator_t it = nvs_entry_find(NVS_DEFAULT_PART_NAME, PARAM_NAMESPACE, NVS_TYPE_ANY);
        size_t erased_count = 0;
        
        while (it != NULL) {
            nvs_entry_info_t info;
            nvs_entry_info(it, &info);
            
            esp_err_t erase_err = nvs_erase_key(nvs, info.key);
            if (erase_err == ESP_OK) {
                erased_count++;
                ESP_LOGI(TAG, "Erased key: %s", info.key);
            } else {
                ESP_LOGW(TAG, "Failed to erase key %s: %s", info.key, esp_err_to_name(erase_err));
            }
            
            it = nvs_entry_next(it);
        }
        nvs_release_iterator(it);

        cJSON_AddStringToObject(data, "configType", "erase");
        cJSON_AddNumberToObject(data, "erasedKeys", erased_count);
        
        message = "All configuration data erased successfully";
        restart_required = true;

    } else if (strcmp(func_param, "advanced") == 0) {
        // Advanced configuration - reuse logic from advanced handler
        nvs_close(nvs);
        return api_advanced_post_handler(req);

    } else if (strcmp(func_param, "lock") == 0) {
        // Lock configuration
        char lock_password[65] = {0};
        readUrlParameterIntoBuffer(buf, "lock_password", lock_password, sizeof(lock_password));
        sanitize_string_input(lock_password, sizeof(lock_password));

        if (strlen(lock_password) < 4) {
            nvs_close(nvs);
            api_response_t response = {
                .success = false,
                .message = "Lock password must be at least 4 characters",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        nvs_set_str(nvs, "lock_pass", lock_password);
        lockUI();

        cJSON_AddStringToObject(data, "configType", "lock");
        cJSON_AddBoolToObject(data, "locked", true);
        
        message = "System locked successfully";

    } else {
        nvs_close(nvs);
        api_response_t response = {
            .success = false,
            .message = "Invalid function parameter",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }

    // Commit changes
    esp_err_t commit_err = nvs_commit(nvs);
    nvs_close(nvs);

    if (commit_err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit configuration: %s", esp_err_to_name(commit_err));
        cJSON_Delete(data);
        api_response_t response = {
            .success = false,
            .message = "Failed to save configuration",
            .status_code = 500
        };
        return send_api_response(req, &response);
    }

    // Add common response data
    cJSON_AddBoolToObject(data, "restartRequired", restart_required);
    if (restart_required) {
        cJSON_AddNumberToObject(data, "restartDelay", 3);
    }

    api_response_t response = {
        .success = true,
        .message = message,
        .data = data,
        .status_code = 200
    };

    esp_err_t result = send_api_response(req, &response);

    // Schedule restart if required
    if (restart_required) {
        ESP_LOGI(TAG, "Scheduling system restart in 3 seconds");
        restartByTimerinS(3);
    }

    return result;
}