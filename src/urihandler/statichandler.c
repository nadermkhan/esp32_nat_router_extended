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
    extern const unsigned char styles_start[] asm("_binary_index_DpOF12W4_css_start");
    httpd_resp_set_type(req, "text/css");
    ESP_LOGD(TAG_HANDLER, "Requesting style");
    return download(req, (const char *)styles_start);
}

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

esp_err_t spa_get_handler(httpd_req_t *req)
{
    extern const char index_html_start[] asm("_binary_index_html_start");
    extern const char index_html_end[] asm("_binary_index_html_end");
    
    httpd_resp_set_type(req, "text/html");
    closeHeader(req);
    
    ESP_LOGI(TAG_HANDLER, "Serving React SPA from embedded index.html");
    return httpd_resp_send(req, index_html_start, index_html_end - index_html_start);
}
esp_err_t react_css_get_handler(httpd_req_t *req)
{
       extern const unsigned char styles_start[] asm("_binary_index_DpOF12W4_css_start");
    httpd_resp_set_type(req, "text/css");
    ESP_LOGD(TAG_HANDLER, "Requesting style");
    return download(req, (const char *)styles_start);
}

esp_err_t react_vendor_js_get_handler(httpd_req_t *req)
{
   
    extern const unsigned char vendorjs_start_lol[] asm("_binary_vendor_dQk0gtQ5_js_start");
    
      
    httpd_resp_set_type(req, "text/javascript");
    ESP_LOGD(TAG_HANDLER, "Requesting style");
    return download(req, (const char *)vendorjs_start_lol);

}

esp_err_t react_ui_js_get_handler(httpd_req_t *req)
{
    
    extern const unsigned char uijs_start_lol[] asm("_binary_ui_CGN5kbBo_js_start");
     httpd_resp_set_type(req, "text/javascript");
    ESP_LOGD(TAG_HANDLER, "Requesting style");
    return download(req, (const char *)uijs_start_lol);
}

esp_err_t react_router_js_get_handler(httpd_req_t *req)
{
     extern const char routerjs_start_lol[] asm("_binary_router_DuyDbDLs_js_start");
     httpd_resp_set_type(req, "text/javascript");
    ESP_LOGD(TAG_HANDLER, "Requesting style");
    return download(req, (const char *)routerjs_start_lol);
    }

esp_err_t react_index_js_get_handler(httpd_req_t *req)
{
     extern const char reactindxjs_start_lol[] asm("_binary_index_DUflLXBX_js_start");
     httpd_resp_set_type(req, "text/javascript");
    ESP_LOGD(TAG_HANDLER, "Requesting style");
    return download(req, (const char *)reactindxjs_start_lol);

}