#include "urihandler/handler.h"
#include "router_globals.h"
#include "timer.h"

static const char *TAG = "HTTPServer";

// Global server handles
extern server_config_t server_config;

// API endpoints - GET
static httpd_uri_t api_about = {
    .uri = "/api/about", 
    .method = HTTP_GET, 
    .handler = api_about_get_handler
};

static httpd_uri_t api_system = {
    .uri = "/api/system", 
    .method = HTTP_GET, 
    .handler = api_system_get_handler
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

// HTTPS API endpoints - GET
static httpd_uri_t api_https_config = {
    .uri = "/api/https/config", 
    .method = HTTP_GET, 
    .handler = api_https_config_get_handler
};

static httpd_uri_t api_https_cert_info = {
    .uri = "/api/https/cert/info", 
    .method = HTTP_GET, 
    .handler = api_https_cert_info_get_handler
};

// API endpoints - POST
static httpd_uri_t api_system_restart = {
    .uri = "/api/system/restart", 
    .method = HTTP_POST, 
    .handler = api_system_restart_post_handler
};

static httpd_uri_t api_config_post = {
    .uri = "/api/config", 
    .method = HTTP_POST, 
    .handler = api_config_post_handler
};

static httpd_uri_t api_advanced_post = {
    .uri = "/api/advanced", 
    .method = HTTP_POST, 
    .handler = api_advanced_post_handler
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

static httpd_uri_t api_clients_block = {
    .uri = "/api/clients/block", 
    .method = HTTP_POST, 
    .handler = api_clients_block_post_handler
};

static httpd_uri_t api_clients_unblock = {
    .uri = "/api/clients/unblock", 
    .method = HTTP_POST, 
    .handler = api_clients_unblock_post_handler
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

static httpd_uri_t api_scan_start_post = {
    .uri = "/api/scan/start", 
    .method = HTTP_POST, 
    .handler = api_scan_start_post_handler
};

// HTTPS API endpoints - POST
static httpd_uri_t api_https_config_post = {
    .uri = "/api/https/config", 
    .method = HTTP_POST, 
    .handler = api_https_config_post_handler
};

static httpd_uri_t api_https_cert_upload = {
    .uri = "/api/https/cert/upload", 
    .method = HTTP_POST, 
    .handler = api_https_cert_upload_post_handler
};

static httpd_uri_t api_https_cert_generate = {
    .uri = "/api/https/cert/generate", 
    .method = HTTP_POST, 
    .handler = api_https_cert_generate_post_handler
};

// Legacy REST API endpoint (keep for backward compatibility)
static httpd_uri_t rest_api = {
    .uri = "/rest",
    .method = HTTP_GET,
    .handler = rest_handler,
};

// Simple root endpoint that returns API information
static httpd_uri_t api_root = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = api_root_handler,
};

// API documentation endpoint
static httpd_uri_t api_docs = {
    .uri = "/api",
    .method = HTTP_GET,
    .handler = api_docs_handler,
};

// HTTP to HTTPS redirect handler
static httpd_uri_t http_redirect = {
    .uri = "/*",
    .method = HTTP_GET,
    .handler = http_redirect_to_https,
    .user_ctx = NULL
};

// 404 handler for non-API endpoints
static httpd_uri_t catchall_404 = {
    .uri = "/*", 
    .method = HTTP_GET, 
    .handler = api_404_handler
};

// Register HTTP URI handlers (full functionality)
void register_http_uri_handlers(void) {
    if (!server_config.http_server) {
        ESP_LOGE(TAG, "HTTP server not initialized");
        return;
    }

    ESP_LOGI(TAG, "Registering HTTP URI handlers (API-only mode)");

    // Register root and documentation endpoints
    httpd_register_uri_handler(server_config.http_server, &api_root);
    httpd_register_uri_handler(server_config.http_server, &api_docs);

    // Register API endpoints - GET
    httpd_register_uri_handler(server_config.http_server, &api_about);
    httpd_register_uri_handler(server_config.http_server, &api_system);
    httpd_register_uri_handler(server_config.http_server, &api_advanced);
    httpd_register_uri_handler(server_config.http_server, &api_clients);
    httpd_register_uri_handler(server_config.http_server, &api_config);
    httpd_register_uri_handler(server_config.http_server, &api_lock);
    httpd_register_uri_handler(server_config.http_server, &api_portmap);
    httpd_register_uri_handler(server_config.http_server, &api_scan_result);
    httpd_register_uri_handler(server_config.http_server, &api_https_config);
    httpd_register_uri_handler(server_config.http_server, &api_https_cert_info);

    // Register API endpoints - POST
    httpd_register_uri_handler(server_config.http_server, &api_system_restart);
    httpd_register_uri_handler(server_config.http_server, &api_config_post);
    httpd_register_uri_handler(server_config.http_server, &api_advanced_post);
    httpd_register_uri_handler(server_config.http_server, &api_apply_post);
    httpd_register_uri_handler(server_config.http_server, &api_portmap_post);
    httpd_register_uri_handler(server_config.http_server, &api_clients_block);
    httpd_register_uri_handler(server_config.http_server, &api_clients_unblock);
    httpd_register_uri_handler(server_config.http_server, &api_lock_post);
    httpd_register_uri_handler(server_config.http_server, &api_unlock_post);
    httpd_register_uri_handler(server_config.http_server, &api_scan_start_post);
    httpd_register_uri_handler(server_config.http_server, &api_https_config_post);
    httpd_register_uri_handler(server_config.http_server, &api_https_cert_upload);
    httpd_register_uri_handler(server_config.http_server, &api_https_cert_generate);

    // Keep existing REST API endpoint for backward compatibility
    httpd_register_uri_handler(server_config.http_server, &rest_api);

    // Register 404 catch-all LAST
    httpd_register_uri_handler(server_config.http_server, &catchall_404);

    // Set error handler
    httpd_register_err_handler(server_config.http_server, HTTPD_404_NOT_FOUND, http_404_error_handler);

    ESP_LOGI(TAG, "HTTP server handlers registered successfully (API-only)");
}

// Register HTTPS URI handlers (same as HTTP)
void register_https_uri_handlers(void) {
    if (!server_config.https_server) {
        ESP_LOGE(TAG, "HTTPS server not initialized");
        return;
    }

    ESP_LOGI(TAG, "Registering HTTPS URI handlers (API-only mode)");

    // Register root and documentation endpoints
    httpd_register_uri_handler(server_config.https_server, &api_root);
    httpd_register_uri_handler(server_config.https_server, &api_docs);

    // Register API endpoints - GET
    httpd_register_uri_handler(server_config.https_server, &api_about);
    httpd_register_uri_handler(server_config.https_server, &api_system);
    httpd_register_uri_handler(server_config.https_server, &api_advanced);
    httpd_register_uri_handler(server_config.https_server, &api_clients);
    httpd_register_uri_handler(server_config.https_server, &api_config);
    httpd_register_uri_handler(server_config.https_server, &api_lock);
    httpd_register_uri_handler(server_config.https_server, &api_portmap);
    httpd_register_uri_handler(server_config.https_server, &api_scan_result);
    httpd_register_uri_handler(server_config.https_server, &api_https_config);
    httpd_register_uri_handler(server_config.https_server, &api_https_cert_info);

    // Register API endpoints - POST
    httpd_register_uri_handler(server_config.https_server, &api_system_restart);
    httpd_register_uri_handler(server_config.https_server, &api_config_post);
    httpd_register_uri_handler(server_config.https_server, &api_advanced_post);
    httpd_register_uri_handler(server_config.https_server, &api_apply_post);
    httpd_register_uri_handler(server_config.https_server, &api_portmap_post);
    httpd_register_uri_handler(server_config.https_server, &api_clients_block);
    httpd_register_uri_handler(server_config.https_server, &api_clients_unblock);
    httpd_register_uri_handler(server_config.https_server, &api_lock_post);
    httpd_register_uri_handler(server_config.https_server, &api_unlock_post);
    httpd_register_uri_handler(server_config.https_server, &api_scan_start_post);
    httpd_register_uri_handler(server_config.https_server, &api_https_config_post);
    httpd_register_uri_handler(server_config.https_server, &api_https_cert_upload);
    httpd_register_uri_handler(server_config.https_server, &api_https_cert_generate);

    // Keep existing REST API endpoint for backward compatibility
    httpd_register_uri_handler(server_config.https_server, &rest_api);

    // Register 404 catch-all LAST
    httpd_register_uri_handler(server_config.https_server, &catchall_404);

    // Set error handler
    httpd_register_err_handler(server_config.https_server, HTTPD_404_NOT_FOUND, http_404_error_handler);

    ESP_LOGI(TAG, "HTTPS server handlers registered successfully (API-only)");
}

// Register HTTP redirect handlers (when force HTTPS is enabled)
void register_http_redirect_handlers(void) {
    if (!server_config.http_server) {
        ESP_LOGE(TAG, "HTTP server not initialized");
        return;
    }

    ESP_LOGI(TAG, "Registering HTTP to HTTPS redirect handlers");

    // Register redirect for all HTTP requests
    httpd_register_uri_handler(server_config.http_server, &http_redirect);

    ESP_LOGI(TAG, "HTTP redirect handlers registered successfully");
}

// Legacy function for backward compatibility
httpd_handle_t start_webserver(void) {
    ESP_LOGI(TAG, "Starting web servers...");

    initializeRestartTimer();

    // Check for lock password
    char *lock_pass = NULL;
    get_config_param_str("lock_pass", &lock_pass);
    if (lock_pass != NULL && strlen(lock_pass) > 0) {
        lockUI();
        ESP_LOGI(TAG, "UI is locked with password");
        free(lock_pass);
    }

    // Check keep alive setting
    int32_t keepAlive = 0;
    get_config_param_int("keep_alive", &keepAlive);
    if (keepAlive == 1) {
        initializeKeepAliveTimer();
        ESP_LOGI(TAG, "Keep alive is enabled");
    } else {
        ESP_LOGI(TAG, "Keep alive is disabled");
    }

    // Initialize both HTTP and HTTPS servers
    init_web_servers();

    // Return HTTP server handle for backward compatibility
    return server_config.http_server;
}

// Stop all web servers
void stop_webservers(void) {
    ESP_LOGI(TAG, "Stopping web servers...");
    
    stop_http_server();
    stop_https_server();
    
    // Clean up certificate memory
    if (server_config.cert_info.cert_pem) {
        free(server_config.cert_info.cert_pem);
        server_config.cert_info.cert_pem = NULL;
    }
    if (server_config.cert_info.key_pem) {
        free(server_config.cert_info.key_pem);
        server_config.cert_info.key_pem = NULL;
    }
    
    ESP_LOGI(TAG, "Web servers stopped");
}