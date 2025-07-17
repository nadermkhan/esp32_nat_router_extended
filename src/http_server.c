#include "urihandler/handler.h"

#include "router_globals.h"
#include "timer.h"

static const char *TAG = "HTTPServer";

// Legacy handlers for backward compatibility (if needed)
static httpd_uri_t applyp = {
    .uri = "/apply",
    .method = HTTP_POST,
    .handler = apply_post_handler,
};

static httpd_uri_t applyg = {
    .uri = "/apply",
    .method = HTTP_GET,
    .handler = apply_get_handler,
};

static httpd_uri_t resetg = {
    .uri = "/reset",
    .method = HTTP_GET,
    .handler = reset_get_handler,
};

// SPA routes - serve React app for all main routes
static httpd_uri_t spa_routes[] = {
    {.uri = "/", .method = HTTP_GET, .handler = spa_get_handler},
    {.uri = "/about", .method = HTTP_GET, .handler = spa_get_handler},
    {.uri = "/advanced", .method = HTTP_GET, .handler = spa_get_handler},
    {.uri = "/clients", .method = HTTP_GET, .handler = spa_get_handler},
    {.uri = "/portmap", .method = HTTP_GET, .handler = spa_get_handler},
    {.uri = "/ota", .method = HTTP_GET, .handler = spa_get_handler},
    {.uri = "/scan", .method = HTTP_GET, .handler = spa_get_handler},
    {.uri = "/result", .method = HTTP_GET, .handler = spa_get_handler},
    {.uri = "/lock", .method = HTTP_GET, .handler = spa_get_handler},
    {.uri = "/unlock", .method = HTTP_GET, .handler = spa_get_handler},
};

// API endpoints - GET
static httpd_uri_t api_about = {
    .uri = "/api/about", 
    .method = HTTP_GET, 
    .handler = api_about_get_handler
};

static httpd_uri_t api_advanced = {
    .uri = "/api/advanced", 
    .method = HTTP_GET, 
    .handler = api_advanced_get_handler
};

static httpd_uri_t api_clients = {
    .uri = "/api/clients", 
    .method = HTTP_GET, 
    .handler = api_clients_get_handler
};

static httpd_uri_t api_config = {
    .uri = "/api/config", 
    .method = HTTP_GET, 
    .handler = api_config_get_handler
};

static httpd_uri_t api_lock = {
    .uri = "/api/lock", 
    .method = HTTP_GET, 
    .handler = api_lock_get_handler
};

static httpd_uri_t api_ota = {
    .uri = "/api/ota", 
    .method = HTTP_GET, 
    .handler = api_ota_get_handler
};

static httpd_uri_t api_portmap = {
    .uri = "/api/portmap", 
    .method = HTTP_GET, 
    .handler = api_portmap_get_handler
};

static httpd_uri_t api_scan_result = {
    .uri = "/api/scan/result", 
    .method = HTTP_GET, 
    .handler = api_scan_result_get_handler
};

static httpd_uri_t api_ota_status = {
    .uri = "/api/ota/status", 
    .method = HTTP_GET, 
    .handler = api_ota_status_get_handler
};

static httpd_uri_t api_apply_get = {
    .uri = "/api/apply", 
    .method = HTTP_GET, 
    .handler = api_apply_get_handler
};

// API endpoints - POST
static httpd_uri_t api_config_post = {
    .uri = "/api/config", 
    .method = HTTP_POST, 
    .handler = api_config_post_handler
};

static httpd_uri_t api_apply_post = {
    .uri = "/api/apply", 
    .method = HTTP_POST, 
    .handler = api_apply_post_handler
};

static httpd_uri_t api_portmap_post = {
    .uri = "/api/portmap", 
    .method = HTTP_POST, 
    .handler = api_portmap_post_handler
};

static httpd_uri_t api_lock_post = {
    .uri = "/api/lock", 
    .method = HTTP_POST, 
    .handler = api_lock_post_handler
};

static httpd_uri_t api_unlock_post = {
    .uri = "/api/unlock", 
    .method = HTTP_POST, 
    .handler = api_unlock_post_handler
};

static httpd_uri_t api_ota_check_post = {
    .uri = "/api/ota/check", 
    .method = HTTP_POST, 
    .handler = api_ota_check_post_handler
};

static httpd_uri_t api_ota_start_post = {
    .uri = "/api/ota/start", 
    .method = HTTP_POST, 
    .handler = api_ota_start_post_handler
};

static httpd_uri_t api_scan_start_post = {
    .uri = "/api/scan/start", 
    .method = HTTP_POST, 
    .handler = api_scan_start_post_handler
};

// Static assets for React
static httpd_uri_t react_index_js = {
    .uri = "/assets/index-iP8dXgYc.js", 
    .method = HTTP_GET, 
    .handler = react_index_js_get_handler
};

static httpd_uri_t react_router_js = {
    .uri = "/assets/router-DuyDbDLs.js", 
    .method = HTTP_GET, 
    .handler = react_router_js_get_handler
};

static httpd_uri_t react_ui_js = {
    .uri = "/assets/ui-CGN5kbBo.js", 
    .method = HTTP_GET, 
    .handler = react_ui_js_get_handler
};

static httpd_uri_t react_vendor_js = {
    .uri = "/assets/vendor-dQk0gtQ5.js", 
    .method = HTTP_GET, 
    .handler = react_vendor_js_get_handler
};

static httpd_uri_t react_css = {
    .uri = "/assets/index-O1a2Fugk.css", 
    .method = HTTP_GET, 
    .handler = react_css_get_handler
};

// Keep existing handlers
static httpd_uri_t favicon_handler = {
    .uri = "/favicon.ico",
    .method = HTTP_GET,
    .handler = favicon_get_handler,
    .user_ctx = NULL
};

static httpd_uri_t rest_api = {
    .uri = "/rest",
    .method = HTTP_GET,
    .handler = rest_handler,
};

// Catch-all for SPA routing (must be registered last)
static httpd_uri_t catchall = {
    .uri = "/*", 
    .method = HTTP_GET, 
    .handler = spa_get_handler
};

httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 35; // Increased for more handlers
    config.stack_size = 16384;
    config.lru_purge_enable = true;

    initializeRestartTimer();

    char *lock_pass = NULL;
    int32_t keepAlive = 0;

    get_config_param_str("lock_pass", &lock_pass);
    if (lock_pass != NULL && strlen(lock_pass) > 0)
    {
        lockUI();
        ESP_LOGI(TAG, "UI is locked with password '%s'", lock_pass);
    }
    get_config_param_int("keep_alive", &keepAlive);
    if (keepAlive == 1)
    {
        initializeKeepAliveTimer();
        ESP_LOGI(TAG, "Keep alive is enabled");
    }
    else
    {
        ESP_LOGI(TAG, "Keep alive is disabled");
    }

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK)
    {
        ESP_LOGI(TAG, "Registering URI handlers");

        // Register SPA routes first (specific routes before catch-all)
        for (int i = 0; i < sizeof(spa_routes)/sizeof(spa_routes[0]); i++) {
            httpd_register_uri_handler(server, &spa_routes[i]);
        }

        // Register API endpoints - GET
        httpd_register_uri_handler(server, &api_about);
        httpd_register_uri_handler(server, &api_advanced);
        httpd_register_uri_handler(server, &api_clients);
        httpd_register_uri_handler(server, &api_config);
        httpd_register_uri_handler(server, &api_lock);
        httpd_register_uri_handler(server, &api_ota);
        httpd_register_uri_handler(server, &api_portmap);
        httpd_register_uri_handler(server, &api_scan_result);
        httpd_register_uri_handler(server, &api_ota_status);
        httpd_register_uri_handler(server, &api_apply_get);

        // Register API endpoints - POST
        httpd_register_uri_handler(server, &api_config_post);
        httpd_register_uri_handler(server, &api_apply_post);
        httpd_register_uri_handler(server, &api_portmap_post);
        httpd_register_uri_handler(server, &api_lock_post);
        httpd_register_uri_handler(server, &api_unlock_post);
        httpd_register_uri_handler(server, &api_ota_check_post);
        httpd_register_uri_handler(server, &api_ota_start_post);
        httpd_register_uri_handler(server, &api_scan_start_post);

        // Register React static assets
        httpd_register_uri_handler(server, &react_index_js);
        httpd_register_uri_handler(server, &react_router_js);
        httpd_register_uri_handler(server, &react_ui_js);
        httpd_register_uri_handler(server, &react_vendor_js);
        httpd_register_uri_handler(server, &react_css);

        // Register other static assets
        httpd_register_uri_handler(server, &favicon_handler);

        // Keep existing REST API endpoint
        httpd_register_uri_handler(server, &rest_api);

        // Keep legacy handlers for backward compatibility (optional)
        httpd_register_uri_handler(server, &applyg);
        httpd_register_uri_handler(server, &applyp);
        httpd_register_uri_handler(server, &resetg);

        // Register catch-all LAST (this handles client-side routing)
        httpd_register_uri_handler(server, &catchall);

        // Set error handler
        httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, http_404_error_handler);

        ESP_LOGI(TAG, "Web server started successfully with %d handlers", 
                 sizeof(spa_routes)/sizeof(spa_routes[0]) + 20); // Approximate count

        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}