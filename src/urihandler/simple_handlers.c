#include "handler.h"

static const char *TAG = "SimpleHandlers";

// Global server configuration
server_config_t server_config = {0};

esp_err_t api_root_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "name", "ESP32 NAT Router Extended");
    cJSON_AddStringToObject(json, "version", "1.0.0");
    cJSON_AddStringToObject(json, "description", "Production-ready API-only router management");
    cJSON_AddStringToObject(json, "documentation", "/api");
    
    cJSON *endpoints = cJSON_CreateArray();
    cJSON_AddItemToArray(endpoints, cJSON_CreateString("/api/about"));
    cJSON_AddItemToArray(endpoints, cJSON_CreateString("/api/system"));
    cJSON_AddItemToArray(endpoints, cJSON_CreateString("/api/config"));
    cJSON_AddItemToArray(endpoints, cJSON_CreateString("/api/advanced"));
    cJSON_AddItemToArray(endpoints, cJSON_CreateString("/api/clients"));
    cJSON_AddItemToArray(endpoints, cJSON_CreateString("/api/portmap"));
    cJSON_AddItemToArray(endpoints, cJSON_CreateString("/api/https/config"));
    
    cJSON_AddItemToObject(json, "endpoints", endpoints);
    
    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    
    free(json_string);
    cJSON_Delete(json);
    return ret;
}

esp_err_t api_docs_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "title", "ESP32 NAT Router API Documentation");
    cJSON_AddStringToObject(json, "version", "1.0.0");
    cJSON_AddStringToObject(json, "baseUrl", "/api");
    cJSON_AddStringToObject(json, "documentation", "https://github.com/dchristl/esp32_nat_router_extended");
    
    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    
    free(json_string);
    cJSON_Delete(json);
    return ret;
}

esp_err_t api_404_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_status(req, "404 Not Found");
    
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", false);
    cJSON_AddStringToObject(json, "message", "Endpoint not found");
    cJSON_AddStringToObject(json, "documentation", "/api");
    
    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    
    free(json_string);
    cJSON_Delete(json);
    return ret;
}

esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err) {
    return api_404_handler(req);
}

esp_err_t http_redirect_to_https(httpd_req_t *req) {
    if (!server_config.force_https) {
        return api_404_handler(req);
    }
    
    // Get host header
    size_t buf_len = 64;
    char *host = malloc(buf_len);
    if (httpd_req_get_hdr_value_str(req, "Host", host, buf_len) != ESP_OK) {
        free(host);
        return ESP_FAIL;
    }
    
    // Remove port if present
    char *port_pos = strchr(host, ':');
    if (port_pos) {
        *port_pos = '\0';
    }
    
    // Build HTTPS URL
    char redirect_url[256];
    if (HTTPS_SERVER_PORT == 443) {
        snprintf(redirect_url, sizeof(redirect_url), "https://%s%s", host, req->uri);
    } else {
        snprintf(redirect_url, sizeof(redirect_url), "https://%s:%d%s", 
                host, HTTPS_SERVER_PORT, req->uri);
    }
    
    // Send redirect response
    httpd_resp_set_status(req, "301 Moved Permanently");
    httpd_resp_set_hdr(req, "Location", redirect_url);
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_send(req, "Redirecting to HTTPS", HTTPD_RESP_USE_STRLEN);
    
    free(host);
    ESP_LOGI(TAG, "Redirected HTTP request to HTTPS: %s", redirect_url);
    return ESP_OK;
}

// Helper functions
bool parse_mac_address(const char *mac_str, uint8_t *mac) {
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

void format_mac_address(uint8_t *mac, char *mac_str, size_t size) {
    snprintf(mac_str, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Initialize web servers
void init_web_servers(void) {
    // Load configuration from NVS
    nvs_handle_t nvs;
    bool https_enabled = false; // Start with HTTP only for simplicity
    bool http_enabled = true;
    bool force_https = false;
    
    if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK) {
        int32_t val;
        if (nvs_get_i32(nvs, "https_enabled", &val) == ESP_OK) {
            https_enabled = (val == 1);
        }
        if (nvs_get_i32(nvs, "http_enabled", &val) == ESP_OK) {
            http_enabled = (val == 1);
        }
        if (nvs_get_i32(nvs, "force_https", &val) == ESP_OK) {
            force_https = (val == 1);
        }
        nvs_close(nvs);
    }
    
    server_config.force_https = force_https;
    
    // Start HTTP server
    if (http_enabled) {
        esp_err_t ret = start_http_server();
        if (ret != ESP_OK) {
            ESP_LOGE("INIT", "Failed to start HTTP server");
        }
    }
    
    // Start HTTPS server if enabled
    if (https_enabled) {
        esp_err_t ret = start_https_server();
        if (ret != ESP_OK) {
            ESP_LOGE("INIT", "Failed to start HTTPS server, continuing with HTTP only");
        }
    }
    
    ESP_LOGI("INIT", "Web servers initialized - HTTPS: %s, HTTP: %s",
             server_config.https_enabled ? "enabled" : "disabled",
             server_config.http_enabled ? "enabled" : "disabled");
}

// Simplified server start/stop functions
esp_err_t start_http_server(void) {
    if (server_config.http_server) {
        ESP_LOGW("HTTP", "HTTP server already running");
        return ESP_OK;
    }
    
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = HTTP_SERVER_PORT;
    config.max_open_sockets = 7;
    config.max_uri_handlers = 25;
    config.stack_size = 8192;
    config.task_priority = 5;
    config.lru_purge_enable = true;
    
    esp_err_t ret = httpd_start(&server_config.http_server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE("HTTP", "Failed to start HTTP server: %s", esp_err_to_name(ret));
        return ret;
    }
        // Register URI handlers
    if (server_config.force_https) {
        register_http_redirect_handlers();
    } else {
        register_http_uri_handlers();
    }
    
    server_config.http_enabled = true;
    ESP_LOGI("HTTP", "HTTP server started on port %d", HTTP_SERVER_PORT);
    
    return ESP_OK;
}

esp_err_t stop_http_server(void) {
    if (server_config.http_server) {
        httpd_stop(server_config.http_server);
        server_config.http_server = NULL;
        server_config.http_enabled = false;
        ESP_LOGI("HTTP", "HTTP server stopped");
    }
    return ESP_OK;
}

esp_err_t start_https_server(void) {
    // For now, just return OK - HTTPS implementation can be added later
    ESP_LOGI("HTTPS", "HTTPS server not implemented yet");
    return ESP_OK;
}

esp_err_t stop_https_server(void) {
    // For now, just return OK
    return ESP_OK;
}

esp_err_t generate_self_signed_cert(void) {
    // For now, just return OK
    ESP_LOGI("HTTPS", "Certificate generation not implemented yet");
    return ESP_OK;
}

// Placeholder HTTPS handlers
esp_err_t api_https_config_get_handler(httpd_req_t *req) {
    api_response_t response = {
        .success = false,
        .message = "HTTPS not implemented yet",
        .status_code = 501
    };
    return send_api_response(req, &response);
}

esp_err_t api_https_config_post_handler(httpd_req_t *req) {
    api_response_t response = {
        .success = false,
        .message = "HTTPS not implemented yet",
        .status_code = 501
    };
    return send_api_response(req, &response);
}

esp_err_t api_https_cert_upload_post_handler(httpd_req_t *req) {
    api_response_t response = {
        .success = false,
        .message = "HTTPS not implemented yet",
        .status_code = 501
    };
    return send_api_response(req, &response);
}

esp_err_t api_https_cert_generate_post_handler(httpd_req_t *req) {
    api_response_t response = {
        .success = false,
        .message = "HTTPS not implemented yet",
        .status_code = 501
    };
    return send_api_response(req, &response);
}

esp_err_t api_https_cert_info_get_handler(httpd_req_t *req) {
    api_response_t response = {
        .success = false,
        .message = "HTTPS not implemented yet",
        .status_code = 501
    };
    return send_api_response(req, &response);
}