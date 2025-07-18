#include "handler.h"
#include "cJSON.h"

static const char *TAG_HANDLER = "StaticHandler";

void closeHeader(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "Connection", "close");
}

esp_err_t download(httpd_req_t *req, const char *fileStart)
{
    httpd_resp_set_hdr(req, "Cache-Control", "max-age=31536000");
    closeHeader(req);
    return httpd_resp_send(req, fileStart, HTTPD_RESP_USE_STRLEN);
}

esp_err_t styles_download_get_handler(httpd_req_t *req)
{
    extern const unsigned char styles_start[] asm("_binary_styles_67aa3b0203355627b525be2ea57be7bf_css_start");
    httpd_resp_set_type(req, "text/css");
    ESP_LOGD(TAG_HANDLER, "Requesting style");
    return download(req, (const char *)styles_start);
}

esp_err_t jquery_get_handler(httpd_req_t *req)
{
    extern const unsigned char jquery_js_start[] asm("_binary_jquery_8a1045d9cbf50b52a0805c111ba08e94_js_start");
    httpd_resp_set_type(req, "text/javascript");
    ESP_LOGD(TAG_HANDLER, "Requesting jquery");
    return download(req, (const char *)jquery_js_start);
}

// Handler to download a "favicon.ico" file kept on the server
esp_err_t favicon_get_handler(httpd_req_t *req)
{
    extern const char favicon_ico_start[] asm("_binary_favicon_ico_start");
    extern const char favicon_ico_end[] asm("_binary_favicon_ico_end");
    const size_t favicon_ico_size = (favicon_ico_end - favicon_ico_start);
    httpd_resp_set_type(req, "image/x-icon");
    ESP_LOGD(TAG_HANDLER, "Requesting favicon");
    closeHeader(req);
    return httpd_resp_send(req, favicon_ico_start, favicon_ico_size);
}

esp_err_t redirectToRoot(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Temporary Redirect");
    char *currentIP = getDefaultIPByNetmask();
    char str[strlen("http://") + strlen(currentIP) + 1];
    strcpy(str, "http://");
    strcat(str, currentIP);
    httpd_resp_set_hdr(req, "Location", str);
    httpd_resp_set_hdr(req, "Connection", "Close");
    httpd_resp_send(req, "", HTTPD_RESP_USE_STRLEN);
    free(currentIP);

    return ESP_OK;
}

esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    httpd_resp_set_status(req, "302 Temporary Redirect");
    httpd_resp_set_hdr(req, "Location", "/");
    return httpd_resp_send(req, NULL, 0);
}

// Updated reset handler - returns JSON instead of HTML to avoid missing binary
esp_err_t reset_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    closeHeader(req);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "message", "Device reset initiated");
    cJSON_AddBoolToObject(json, "success", true);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);
    
    free(json_string);
    cJSON_Delete(json);
    return ret;
}

// ===== NEW SPA AND REACT HANDLERS =====

// SPA Handler - serves your React app
esp_err_t spa_get_handler(httpd_req_t *req)
{
    // Serve your React build's index.html
    // Adjust the binary name to match your actual embedded file
    extern const char index_html_start[] asm("_binary_index_html_start");
    extern const char index_html_end[] asm("_binary_index_html_end");
    
    httpd_resp_set_type(req, "text/html");
    closeHeader(req);
    
    ESP_LOGD(TAG_HANDLER, "Serving React SPA");
    return httpd_resp_send(req, index_html_start, 
                          index_html_end - index_html_start);
}

// React Asset Handlers
esp_err_t react_css_get_handler(httpd_req_t *req)
{
    extern const char react_css_start[] asm("_binary_react_css_start");
    
    httpd_resp_set_type(req, "text/css");
    ESP_LOGD(TAG_HANDLER, "Serving React CSS");
    return download(req, (const char *)react_css_start);
}

esp_err_t react_vendor_js_get_handler(httpd_req_t *req)
{
    extern const char react_vendor_js_start[] asm("_binary_react_vendor_js_start");
    
    httpd_resp_set_type(req, "application/javascript");
    ESP_LOGD(TAG_HANDLER, "Serving React Vendor JS");
    return download(req, (const char *)react_vendor_js_start);
}

esp_err_t react_ui_js_get_handler(httpd_req_t *req)
{
    extern const char react_ui_js_start[] asm("_binary_react_ui_js_start");
    
    httpd_resp_set_type(req, "application/javascript");
    ESP_LOGD(TAG_HANDLER, "Serving React UI JS");
    return download(req, (const char *)react_ui_js_start);
}

esp_err_t react_router_js_get_handler(httpd_req_t *req)
{
    extern const char react_router_js_start[] asm("_binary_react_router_js_start");
    
    httpd_resp_set_type(req, "application/javascript");
    ESP_LOGD(TAG_HANDLER, "Serving React Router JS");
    return download(req, (const char *)react_router_js_start);
}

esp_err_t react_index_js_get_handler(httpd_req_t *req)
{
    extern const char react_index_js_start[] asm("_binary_react_index_js_start");
    
    httpd_resp_set_type(req, "application/javascript");
    ESP_LOGD(TAG_HANDLER, "Serving React Index JS");
    return download(req, (const char *)react_index_js_start);
}