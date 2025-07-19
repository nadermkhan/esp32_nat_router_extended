#include "handler.h"
#include <esp_system.h>
#include <esp_heap_caps.h>
#include <esp_flash.h>
#include <esp_partition.h>

static const char *TAG = "SystemHandler";

esp_err_t api_system_get_handler(httpd_req_t *req) {
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
    
    // Memory information
    cJSON *memory = cJSON_CreateObject();
    multi_heap_info_t heap_info;
    heap_caps_get_info(&heap_info, MALLOC_CAP_DEFAULT);
    
    cJSON_AddNumberToObject(memory, "total", heap_info.total_allocated_bytes + heap_info.total_free_bytes);
    cJSON_AddNumberToObject(memory, "free", heap_info.total_free_bytes);
    cJSON_AddNumberToObject(memory, "used", heap_info.total_allocated_bytes);
    cJSON_AddNumberToObject(memory, "largest_free_block", heap_info.largest_free_block);
    cJSON_AddNumberToObject(memory, "minimum_free", heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT));
    
    // Calculate percentage
    float usage_percent = ((float)heap_info.total_allocated_bytes / 
                          (heap_info.total_allocated_bytes + heap_info.total_free_bytes)) * 100.0f;
    cJSON_AddNumberToObject(memory, "usage_percent", usage_percent);
    
    cJSON_AddItemToObject(data, "memory", memory);

    // Flash information
    cJSON *flash = cJSON_CreateObject();
    size_t flash_size;
    if (esp_flash_get_size(NULL, &flash_size) == ESP_OK) {
        cJSON_AddNumberToObject(flash, "size", flash_size);
    }
    
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running) {
        cJSON_AddStringToObject(flash, "running_partition", running->label);
        cJSON_AddNumberToObject(flash, "partition_size", running->size);
    }
    
    cJSON_AddItemToObject(data, "flash", flash);

    // System information
    cJSON *system = cJSON_CreateObject();
    cJSON_AddNumberToObject(system, "uptime", esp_timer_get_time() / 1000000); // seconds
    cJSON_AddNumberToObject(system, "free_heap", esp_get_free_heap_size());
    cJSON_AddNumberToObject(system, "minimum_free_heap", esp_get_minimum_free_heap_size());
    
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    cJSON_AddStringToObject(system, "chip_model", CONFIG_IDF_TARGET);
    cJSON_AddNumberToObject(system, "chip_revision", chip_info.revision);
    cJSON_AddNumberToObject(system, "cpu_cores", chip_info.cores);
    
    cJSON_AddItemToObject(data, "system", system);

    // Task information
    cJSON *tasks = cJSON_CreateObject();
    UBaseType_t task_count = uxTaskGetNumberOfTasks();
    cJSON_AddNumberToObject(tasks, "count", task_count);
    
    // Get high water mark for current task
    UBaseType_t stack_high_water = uxTaskGetStackHighWaterMark(NULL);
    cJSON_AddNumberToObject(tasks, "current_task_stack_free", stack_high_water * sizeof(StackType_t));
    
    cJSON_AddItemToObject(data, "tasks", tasks);

    api_response_t response = {
        .success = true,
        .message = "System information retrieved",
        .data = data,
        .status_code = 200
    };
    
    return send_api_response(req, &response);
}

esp_err_t api_system_restart_post_handler(httpd_req_t *req) {
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

    api_response_t response = {
        .success = true,
        .message = "System restart initiated",
        .status_code = 200
    };
    
    esp_err_t ret = send_api_response(req, &response);
    
    // Restart after sending response
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    
    return ret;
}