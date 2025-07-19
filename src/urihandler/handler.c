#include "handler.h"
#include <string.h>
#include <sys/time.h>

static const char *TAG = "APIHandler";
static rate_limit_entry_t rate_limits[10]; // Simple rate limiting for 10 IPs
static bool locked = false;

bool isLocked(void) {
    return locked;
}

void lockUI(void) {
    locked = true;
}

esp_err_t send_api_response(httpd_req_t *req, api_response_t *response) {
    if (!response) {
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "Expires", "0");
    
    if (response->status_code != 200) {
        char status_str[32];
        snprintf(status_str, sizeof(status_str), "%d", response->status_code);
        httpd_resp_set_status(req, status_str);
    }

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", response->success);
    
    if (response->message) {
        cJSON_AddStringToObject(json, "message", response->message);
    }
    
    if (response->data) {
        cJSON_AddItemToObject(json, "data", response->data);
    }

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    
    free(json_string);
    cJSON_Delete(json);
    return ret;
}

bool check_rate_limit(httpd_req_t *req) {
    char client_ip[16] = {0};
    
    // Get client IP from headers or connection
    size_t buf_len = sizeof(client_ip);
    if (httpd_req_get_hdr_value_str(req, "X-Forwarded-For", client_ip, buf_len) != ESP_OK) {
        // Fallback to connection info if available
        strcpy(client_ip, "unknown");
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    int64_t current_time = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    // Find or create rate limit entry
    rate_limit_entry_t *entry = NULL;
    for (int i = 0; i < 10; i++) {
        if (strcmp(rate_limits[i].client_ip, client_ip) == 0) {
            entry = &rate_limits[i];
            break;
        }
        if (strlen(rate_limits[i].client_ip) == 0) {
            entry = &rate_limits[i];
            strcpy(entry->client_ip, client_ip);
            entry->window_start = current_time;
            entry->request_count = 0;
            break;
        }
    }

    if (!entry) {
        // No space, allow request but log warning
        ESP_LOGW(TAG, "Rate limit table full, allowing request");
        return true;
    }

    // Reset window if expired
    if (current_time - entry->window_start > API_RATE_LIMIT_WINDOW) {
        entry->window_start = current_time;
        entry->request_count = 0;
    }

    entry->request_count++;
    
    if (entry->request_count > API_RATE_LIMIT_MAX_REQUESTS) {
        ESP_LOGW(TAG, "Rate limit exceeded for IP: %s", client_ip);
        return false;
    }

    return true;
}

bool validate_request_size(httpd_req_t *req) {
    if (req->content_len > MAX_REQUEST_SIZE) {
        ESP_LOGW(TAG, "Request size too large: %d bytes", req->content_len);
        return false;
    }
    return true;
}

void sanitize_string_input(char *input, size_t max_len) {
    if (!input) return;
    
    size_t len = strlen(input);
    if (len >= max_len) {
        input[max_len - 1] = '\0';
        len = max_len - 1;
    }
    
    // Remove dangerous characters
    for (size_t i = 0; i < len; i++) {
        if (input[i] < 32 || input[i] > 126) {
            if (input[i] != '\n' && input[i] != '\r' && input[i] != '\t') {
                input[i] = '?';
            }
        }
    }
}

bool is_valid_ip_address(const char *ip) {
    if (!ip) return false;
    
    int parts[4];
    int count = sscanf(ip, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]);
    
    if (count != 4) return false;
    
    for (int i = 0; i < 4; i++) {
        if (parts[i] < 0 || parts[i] > 255) {
            return false;
        }
    }
    return true;
}

bool is_valid_port(int port) {
    return port > 0 && port <= 65535;
}