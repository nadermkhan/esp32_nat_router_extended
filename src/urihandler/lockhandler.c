#include "handler.h"
#include "nvs.h"
#include <mbedtls/sha256.h>
#include <string.h>

static const char *TAG = "LockHandler";

static bool locked = false;
static uint32_t failed_attempts = 0;
static int64_t last_attempt_time = 0;
static const uint32_t MAX_FAILED_ATTEMPTS = 5;
static const int64_t LOCKOUT_DURATION = 300000000; // 5 minutes in microseconds

bool isLocked(void) {
    return locked;
}

void lockUI(void) {
    locked = true;
    ESP_LOGI(TAG, "System locked");
}

// Hash password using SHA256
static void hash_password(const char *password, uint8_t *hash) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 for SHA256
    mbedtls_sha256_update(&ctx, (const unsigned char *)password, strlen(password));
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
}

// Check if account is locked due to failed attempts
static bool is_account_locked(void) {
    if (failed_attempts < MAX_FAILED_ATTEMPTS) {
        return false;
    }
    
    int64_t current_time = esp_timer_get_time();
    if (current_time - last_attempt_time > LOCKOUT_DURATION) {
        // Reset failed attempts after lockout period
        failed_attempts = 0;
        return false;
    }
    
    return true;
}

esp_err_t api_lock_get_handler(httpd_req_t *req) {
    if (!check_rate_limit(req)) {
        api_response_t response = {
            .success = false,
            .message = "Rate limit exceeded",
            .status_code = 429
        };
        return send_api_response(req, &response);
    }

    cJSON *data = cJSON_CreateObject();
    cJSON_AddBoolToObject(data, "locked", locked);
    
    char *lock_pass = NULL;
    get_config_param_str("lock_pass", &lock_pass);
    bool has_password = (lock_pass != NULL && strlen(lock_pass) > 0);
    cJSON_AddBoolToObject(data, "hasPassword", has_password);
    
    if (is_account_locked()) {
        int64_t current_time = esp_timer_get_time();
        int64_t remaining_time = (LOCKOUT_DURATION - (current_time - last_attempt_time)) / 1000000;
        cJSON_AddBoolToObject(data, "accountLocked", true);
        cJSON_AddNumberToObject(data, "lockoutRemaining", remaining_time);
    } else {
        cJSON_AddBoolToObject(data, "accountLocked", false);
        cJSON_AddNumberToObject(data, "failedAttempts", failed_attempts);
        cJSON_AddNumberToObject(data, "maxAttempts", MAX_FAILED_ATTEMPTS);
    }

    if (lock_pass) free(lock_pass);

    api_response_t response = {
        .success = true,
        .message = "Lock status retrieved",
        .data = data,
        .status_code = 200
    };

    return send_api_response(req, &response);
}

esp_err_t api_lock_post_handler(httpd_req_t *req) {
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

    char pass_param[65] = {0}, pass2_param[65] = {0};
    readUrlParameterIntoBuffer(buf, "lockpass", pass_param, sizeof(pass_param));
    readUrlParameterIntoBuffer(buf, "lockpass2", pass2_param, sizeof(pass2_param));

    sanitize_string_input(pass_param, sizeof(pass_param));
    sanitize_string_input(pass2_param, sizeof(pass2_param));

    // Validate password requirements
    if (strlen(pass_param) < 4) {
        api_response_t response = {
            .success = false,
            .message = "Password must be at least 4 characters long",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }


        if (strlen(pass_param) > 64) {
        api_response_t response = {
            .success = false,
            .message = "Password must be no more than 64 characters long",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }

    if (strcmp(pass_param, pass2_param) != 0) {
        api_response_t response = {
            .success = false,
            .message = "Passwords do not match",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }

    // Hash the password before storing
    uint8_t password_hash[32];
    hash_password(pass_param, password_hash);
    
    // Convert hash to hex string for storage
    char hash_hex[65] = {0};
    for (int i = 0; i < 32; i++) {
        sprintf(&hash_hex[i * 2], "%02x", password_hash[i]);
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

    esp_err_t set_err = nvs_set_str(nvs, "lock_pass_hash", hash_hex);
    if (set_err == ESP_OK) {
        set_err = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (set_err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save lock password: %s", esp_err_to_name(set_err));
        api_response_t response = {
            .success = false,
            .message = "Failed to save lock password",
            .status_code = 500
        };
        return send_api_response(req, &response);
    }

    // Lock the system if password was set
    if (strlen(pass_param) > 0) {
        lockUI();
    }

    cJSON *data = cJSON_CreateObject();
    cJSON_AddBoolToObject(data, "locked", locked);
    cJSON_AddBoolToObject(data, "passwordSet", true);

    api_response_t response = {
        .success = true,
        .message = "Lock password set successfully",
        .data = data,
        .status_code = 200
    };

    ESP_LOGI(TAG, "Lock password updated and system locked");
    return send_api_response(req, &response);
}

esp_err_t api_unlock_post_handler(httpd_req_t *req) {
    if (!check_rate_limit(req)) {
        api_response_t response = {
            .success = false,
            .message = "Rate limit exceeded",
            .status_code = 429
        };
        return send_api_response(req, &response);
    }

    if (is_account_locked()) {
        int64_t current_time = esp_timer_get_time();
        int64_t remaining_time = (LOCKOUT_DURATION - (current_time - last_attempt_time)) / 1000000;
        
        cJSON *data = cJSON_CreateObject();
        cJSON_AddNumberToObject(data, "lockoutRemaining", remaining_time);
        
        api_response_t response = {
            .success = false,
            .message = "Account temporarily locked due to failed attempts",
            .data = data,
            .status_code = 423
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

    char unlock_param[65] = {0};
    readUrlParameterIntoBuffer(buf, "unlock", unlock_param, sizeof(unlock_param));
    sanitize_string_input(unlock_param, sizeof(unlock_param));

    if (strlen(unlock_param) == 0) {
        failed_attempts++;
        last_attempt_time = esp_timer_get_time();
        
        api_response_t response = {
            .success = false,
            .message = "Password is required",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }

    // Get stored password hash
    char *stored_hash = NULL;
    esp_err_t get_err = get_config_param_str("lock_pass_hash", &stored_hash);
    
    if (get_err != ESP_OK || !stored_hash) {
        // Fallback to old plain text storage for backward compatibility
        char *old_password = NULL;
        get_err = get_config_param_str("lock_pass", &old_password);
        
        if (get_err == ESP_OK && old_password && strcmp(old_password, unlock_param) == 0) {
            // Migrate to hashed storage
            uint8_t password_hash[32];
            hash_password(unlock_param, password_hash);
            
            char hash_hex[65] = {0};
            for (int i = 0; i < 32; i++) {
                sprintf(&hash_hex[i * 2], "%02x", password_hash[i]);
            }
            
            nvs_handle_t nvs;
            if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK) {
                nvs_set_str(nvs, "lock_pass_hash", hash_hex);
                nvs_erase_key(nvs, "lock_pass"); // Remove old plain text
                nvs_commit(nvs);
                nvs_close(nvs);
            }
            
            locked = false;
            failed_attempts = 0;
            
            if (old_password) free(old_password);
            
            cJSON *data = cJSON_CreateObject();
            cJSON_AddBoolToObject(data, "unlocked", true);
            cJSON_AddStringToObject(data, "note", "Password migrated to secure storage");
            
            api_response_t response = {
                .success = true,
                .message = "System unlocked successfully",
                .data = data,
                .status_code = 200
            };
            
            ESP_LOGI(TAG, "System unlocked and password migrated to secure storage");
            return send_api_response(req, &response);
        }
        
        if (old_password) free(old_password);
        
        failed_attempts++;
        last_attempt_time = esp_timer_get_time();
        
        api_response_t response = {
            .success = false,
            .message = "No lock password configured",
            .status_code = 404
        };
        return send_api_response(req, &response);
    }

    // Hash the provided password
    uint8_t provided_hash[32];
    hash_password(unlock_param, provided_hash);
    
    // Convert to hex string for comparison
    char provided_hex[65] = {0};
    for (int i = 0; i < 32; i++) {
        sprintf(&provided_hex[i * 2], "%02x", provided_hash[i]);
    }

    // Compare hashes
    if (strcmp(stored_hash, provided_hex) == 0) {
        locked = false;
        failed_attempts = 0;
        
        cJSON *data = cJSON_CreateObject();
        cJSON_AddBoolToObject(data, "unlocked", true);
        
        api_response_t response = {
            .success = true,
            .message = "System unlocked successfully",
            .data = data,
            .status_code = 200
        };
        
        ESP_LOGI(TAG, "System unlocked successfully");
        free(stored_hash);
        return send_api_response(req, &response);
    } else {
        failed_attempts++;
        last_attempt_time = esp_timer_get_time();
        
        cJSON *data = cJSON_CreateObject();
        cJSON_AddNumberToObject(data, "failedAttempts", failed_attempts);
        cJSON_AddNumberToObject(data, "remainingAttempts", MAX_FAILED_ATTEMPTS - failed_attempts);
        
        api_response_t response = {
            .success = false,
            .message = "Invalid password",
            .data = data,
            .status_code = 401
        };
        
        ESP_LOGW(TAG, "Failed unlock attempt %d/%d", failed_attempts, MAX_FAILED_ATTEMPTS);
        free(stored_hash);
        return send_api_response(req, &response);
    }
}