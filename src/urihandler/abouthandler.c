#include "handler.h"
#include <esp_app_desc.h>
#include <esp_idf_version.h>

static const char *TAG = "AboutHandler";

esp_err_t api_about_get_handler(httpd_req_t *req) {
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

    // Application information
    cJSON *app = cJSON_CreateObject();
    const esp_app_desc_t *app_desc = esp_app_get_description();
    
    cJSON_AddStringToObject(app, "version", app_desc->version);
    cJSON_AddStringToObject(app, "projectName", app_desc->project_name);
    cJSON_AddStringToObject(app, "compileTime", app_desc->time);
    cJSON_AddStringToObject(app, "compileDate", app_desc->date);
    cJSON_AddStringToObject(app, "idfVersion", app_desc->idf_ver);
    
    // Add secure hash if available
    char sha256_str[65] = {0};
    for (int i = 0; i < 32; i++) {
        sprintf(&sha256_str[i * 2], "%02x", app_desc->app_elf_sha256[i]);
    }
    cJSON_AddStringToObject(app, "sha256", sha256_str);
    
    cJSON_AddItemToObject(data, "application", app);

    // Hardware information
    cJSON *hardware = cJSON_CreateObject();
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    
    cJSON_AddStringToObject(hardware, "chipModel", CONFIG_IDF_TARGET);
    cJSON_AddNumberToObject(hardware, "chipRevision", chip_info.revision);
    cJSON_AddNumberToObject(hardware, "cpuCores", chip_info.cores);
    
    // Feature flags
    cJSON *features = cJSON_CreateArray();
    if (chip_info.features & CHIP_FEATURE_WIFI_BGN) {
        cJSON_AddItemToArray(features, cJSON_CreateString("WiFi"));
    }
    if (chip_info.features & CHIP_FEATURE_BT) {
        cJSON_AddItemToArray(features, cJSON_CreateString("Bluetooth"));
    }
    if (chip_info.features & CHIP_FEATURE_BLE) {
        cJSON_AddItemToArray(features, cJSON_CreateString("BLE"));
    }
    if (chip_info.features & CHIP_FEATURE_EMB_FLASH) {
        cJSON_AddItemToArray(features, cJSON_CreateString("Embedded Flash"));
    }
    cJSON_AddItemToObject(hardware, "features", features);
    
    // Flash information
    size_t flash_size;
    if (esp_flash_get_size(NULL, &flash_size) == ESP_OK) {
        cJSON_AddNumberToObject(hardware, "flashSize", flash_size);
        cJSON_AddStringToObject(hardware, "flashSizeHuman", 
            flash_size >= 1024*1024 ? 
                (flash_size >= 1024*1024*16 ? "16MB+" : 
                 flash_size >= 1024*1024*8 ? "8MB" :
                 flash_size >= 1024*1024*4 ? "4MB" : "2MB") : 
                "< 2MB");
    }
    
    cJSON_AddItemToObject(data, "hardware", hardware);

    // Build information
    cJSON *build = cJSON_CreateObject();
    cJSON_AddStringToObject(build, "idfVersion", IDF_VER);
    cJSON_AddStringToObject(build, "compiler", __VERSION__);
    
    #ifdef CONFIG_COMPILER_OPTIMIZATION_SIZE
    cJSON_AddStringToObject(build, "optimization", "size");
    #elif defined(CONFIG_COMPILER_OPTIMIZATION_PERF)
    cJSON_AddStringToObject(build, "optimization", "performance");
    #elif defined(CONFIG_COMPILER_OPTIMIZATION_DEBUG)
    cJSON_AddStringToObject(build, "optimization", "debug");
    #else
    cJSON_AddStringToObject(build, "optimization", "default");
    #endif
    
    #ifdef CONFIG_FREERTOS_UNICORE
    cJSON_AddBoolToObject(build, "unicore", true);
    #else
    cJSON_AddBoolToObject(build, "unicore", false);
    #endif
    
    cJSON_AddItemToObject(data, "build", build);

    // Runtime information
    cJSON *runtime = cJSON_CreateObject();
    cJSON_AddNumberToObject(runtime, "uptimeSeconds", esp_timer_get_time() / 1000000);
    cJSON_AddNumberToObject(runtime, "freeHeap", esp_get_free_heap_size());
    cJSON_AddNumberToObject(runtime, "minimumFreeHeap", esp_get_minimum_free_heap_size());
    
    // Reset reason
    esp_reset_reason_t reset_reason = esp_reset_reason();
    const char *reset_reason_str = "Unknown";
    switch (reset_reason) {
        case ESP_RST_POWERON: reset_reason_str = "Power-on reset"; break;
        case ESP_RST_EXT: reset_reason_str = "External reset"; break;
        case ESP_RST_SW: reset_reason_str = "Software reset"; break;
        case ESP_RST_PANIC: reset_reason_str = "Exception/panic reset"; break;
        case ESP_RST_INT_WDT: reset_reason_str = "Interrupt watchdog reset"; break;
        case ESP_RST_TASK_WDT: reset_reason_str = "Task watchdog reset"; break;
        case ESP_RST_WDT: reset_reason_str = "Other watchdog reset"; break;
        case ESP_RST_DEEPSLEEP: reset_reason_str = "Deep sleep reset"; break;
        case ESP_RST_BROWNOUT: reset_reason_str = "Brownout reset"; break;
        case ESP_RST_SDIO: reset_reason_str = "SDIO reset"; break;
        default: break;
    }
    cJSON_AddStringToObject(runtime, "resetReason", reset_reason_str);
    
    cJSON_AddItemToObject(data, "runtime", runtime);

    // License and credits
    cJSON *legal = cJSON_CreateObject();
    cJSON_AddStringToObject(legal, "license", "MIT License");
    cJSON_AddStringToObject(legal, "author", "ESP32 NAT Router Extended");
    cJSON_AddStringToObject(legal, "repository", "https://github.com/dchristl/esp32_nat_router_extended");
    cJSON_AddStringToObject(legal, "framework", "ESP-IDF");
    cJSON_AddItemToObject(data, "legal", legal);

    api_response_t response = {
        .success = true,
        .message = "System information retrieved successfully",
        .data = data,
        .status_code = 200
    };

    return send_api_response(req, &response);
}