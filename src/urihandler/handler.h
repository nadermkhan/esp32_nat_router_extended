#include <esp_log.h>
#include <esp_http_server.h>
#include "router_globals.h"
#include "lwip/ip4_addr.h"
#include "helper.h"
#include "cmd_system.h"

/* Static Handlers */
void closeHeader(httpd_req_t *req);
esp_err_t styles_download_get_handler(httpd_req_t *req);
esp_err_t jquery_get_handler(httpd_req_t *req);
esp_err_t favicon_get_handler(httpd_req_t *req);
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err);
esp_err_t redirectToRoot(httpd_req_t *req);
esp_err_t reset_get_handler(httpd_req_t *req);

/* SPA Handlers */
esp_err_t spa_get_handler(httpd_req_t *req);

/* React Asset Handlers */
esp_err_t react_index_js_get_handler(httpd_req_t *req);
esp_err_t react_router_js_get_handler(httpd_req_t *req);
esp_err_t react_ui_js_get_handler(httpd_req_t *req);
esp_err_t react_vendor_js_get_handler(httpd_req_t *req);
esp_err_t react_css_get_handler(httpd_req_t *req);

/* Legacy IndexHandler (for backward compatibility) */
esp_err_t index_get_handler(httpd_req_t *req);
esp_err_t index_post_handler(httpd_req_t *req);

/* Lockhandler */
bool isLocked();
void lockUI();
esp_err_t unlock_handler(httpd_req_t *req);
esp_err_t lock_handler(httpd_req_t *req);
esp_err_t redirectToLock(httpd_req_t *req);

/* ScanHandler */
void fillInfoData(char **db, char **textColor);
esp_err_t scan_download_get_handler(httpd_req_t *req);

/* ResultHandler */
esp_err_t result_download_get_handler(httpd_req_t *req);
char *findTextColorForSSID(int8_t rssi);

/* ApplyHandler */
esp_err_t apply_get_handler(httpd_req_t *req);
esp_err_t apply_post_handler(httpd_req_t *req);

/* RestHandler */
esp_err_t rest_handler(httpd_req_t *req);

/* Legacy handlers (for backward compatibility) */
esp_err_t advanced_download_get_handler(httpd_req_t *req);
esp_err_t clients_download_get_handler(httpd_req_t *req);
esp_err_t ota_download_get_handler(httpd_req_t *req);
esp_err_t otalog_get_handler(httpd_req_t *req);
esp_err_t ota_post_handler(httpd_req_t *req);
esp_err_t otalog_post_handler(httpd_req_t *req);
esp_err_t about_get_handler(httpd_req_t *req);
esp_err_t portmap_get_handler(httpd_req_t *req);
esp_err_t portmap_post_handler(httpd_req_t *req);

/* ===== NEW API HANDLERS ===== */

/* API About Handler */
esp_err_t api_about_get_handler(httpd_req_t *req);

/* API Advanced Handler */
esp_err_t api_advanced_get_handler(httpd_req_t *req);

/* API Clients Handler */
esp_err_t api_clients_get_handler(httpd_req_t *req);

/* API Config Handler (Index) */
esp_err_t api_config_get_handler(httpd_req_t *req);
esp_err_t api_config_post_handler(httpd_req_t *req);

/* API Lock Handler */
esp_err_t api_lock_get_handler(httpd_req_t *req);
esp_err_t api_lock_post_handler(httpd_req_t *req);
esp_err_t api_unlock_post_handler(httpd_req_t *req);

/* API OTA Handler */
esp_err_t api_ota_get_handler(httpd_req_t *req);
esp_err_t api_ota_check_post_handler(httpd_req_t *req);
esp_err_t api_ota_start_post_handler(httpd_req_t *req);
esp_err_t api_ota_status_get_handler(httpd_req_t *req);

/* API Portmap Handler */
esp_err_t api_portmap_get_handler(httpd_req_t *req);
esp_err_t api_portmap_post_handler(httpd_req_t *req);

/* API Scan Handler */
esp_err_t api_scan_start_post_handler(httpd_req_t *req);
esp_err_t api_scan_result_get_handler(httpd_req_t *req);

/* API Apply Handler */
esp_err_t api_apply_get_handler(httpd_req_t *req);
esp_err_t api_apply_post_handler(httpd_req_t *req);