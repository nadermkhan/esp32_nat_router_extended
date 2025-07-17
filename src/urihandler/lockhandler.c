#include "handler.h"
#include "timer.h"
#include <sys/param.h>
#include "nvs.h"
#include "router_globals.h"
#include "cJSON.h"

static const char *TAG = "LockHandler";

bool locked = false;

bool isLocked()
{
    return locked;
}

void lockUI()
{
    locked = true;
}

esp_err_t api_unlock_post_handler(httpd_req_t *req)
{
    size_t content_len = req->content_len;
    char buf[content_len + 1];

    httpd_resp_set_type(req, "application/json");
    cJSON *json = cJSON_CreateObject();

    if (fill_post_buffer(req, buf, content_len) == ESP_OK)
    {
        buf[content_len] = '\0';
        char unlockParam[req->content_len];
        readUrlParameterIntoBuffer(buf, "unlock", unlockParam, req->content_len);

        if (strlen(unlockParam) > 0)
        {
            char *lock;
            get_config_param_str("lock_pass", &lock);
            if (strcmp(lock, unlockParam) == 0)
            {
                locked = false;
                cJSON_AddBoolToObject(json, "success", true);
                cJSON_AddStringToObject(json, "message", "Unlocked successfully");
            } else {
                cJSON_AddBoolToObject(json, "success", false);
                cJSON_AddStringToObject(json, "message", "Invalid password");
            }
        } else {
            cJSON_AddBoolToObject(json, "success", false);
            cJSON_AddStringToObject(json, "message", "Password required");
        }
    } else {
        cJSON_AddBoolToObject(json, "success", false);
        cJSON_AddStringToObject(json, "message", "Invalid request");
    }

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    free(json_string);
    cJSON_Delete(json);
    return ret;
}

esp_err_t api_lock_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    cJSON *json = cJSON_CreateObject();
    
    cJSON_AddBoolToObject(json, "locked", locked);
    
    char *lock_pass = NULL;
    get_config_param_str("lock_pass", &lock_pass);
    cJSON_AddBoolToObject(json, "hasPassword", lock_pass != NULL && strlen(lock_pass) > 0);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    free(json_string);
    cJSON_Delete(json);
    return ret;
}

esp_err_t api_lock_post_handler(httpd_req_t *req)
{
    if (isLocked())
    {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Locked");
    }

    size_t content_len = req->content_len;
    char buf[content_len + 1];

    httpd_resp_set_type(req, "application/json");
    cJSON *json = cJSON_CreateObject();

    if (fill_post_buffer(req, buf, content_len) == ESP_OK)
    {
        buf[content_len] = '\0';
        char passParam[req->content_len], pass2Param[req->content_len];

        readUrlParameterIntoBuffer(buf, "lockpass", passParam, req->content_len);
        readUrlParameterIntoBuffer(buf, "lockpass2", pass2Param, req->content_len);
        
        if (strlen(passParam) == strlen(pass2Param) && strcmp(passParam, pass2Param) == 0)
        {
            ESP_LOGI(TAG, "Passwords match. Updating lock password.");
            nvs_handle_t nvs;
            nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
            nvs_set_str(nvs, "lock_pass", passParam);
            nvs_commit(nvs);
            nvs_close(nvs);
            
            if (strlen(passParam) > 0) {
                lockUI();
                cJSON_AddBoolToObject(json, "locked", true);
            }
            cJSON_AddBoolToObject(json, "success", true);
            cJSON_AddStringToObject(json, "message", "Password updated successfully");
        }
        else
        {
            cJSON_AddBoolToObject(json, "success", false);
            cJSON_AddStringToObject(json, "message", "Passwords do not match");
        }
    } else {
        cJSON_AddBoolToObject(json, "success", false);
        cJSON_AddStringToObject(json, "message", "Invalid request");
    }

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    free(json_string);
    cJSON_Delete(json);
    return ret;
}

esp_err_t redirectToLock(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/unlock");
    return httpd_resp_send(req, NULL, 0);
}