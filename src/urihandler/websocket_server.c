#include "websocket_server.h"
#include "websocket_handlers.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "WebSocketServer";
static httpd_handle_t websocket_server = NULL;
static websocket_client_t clients[10];
static int client_count = 0;

esp_err_t websocket_send_json(int fd, cJSON *json)
{
    char *json_string = cJSON_Print(json);
    if (!json_string) {
        return ESP_ERR_NO_MEM;
    }

    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.payload = (uint8_t*)json_string;
    ws_pkt.len = strlen(json_string);
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    esp_err_t ret = httpd_ws_send_frame_async(websocket_server, fd, &ws_pkt);
    free(json_string);
    return ret;
}

esp_err_t websocket_broadcast_json(cJSON *json)
{
    for (int i = 0; i < client_count; i++) {
        if (clients[i].fd > 0) {
            websocket_send_json(clients[i].fd, json);
        }
    }
    return ESP_OK;
}

static void add_client(int fd)
{
    if (client_count < 10) {
        clients[client_count].fd = fd;
        clients[client_count].authenticated = true; // Simplified - no lock check
        client_count++;
        ESP_LOGI(TAG, "Client connected. Total clients: %d", client_count);
    }
}

static void remove_client(int fd)
{
    for (int i = 0; i < client_count; i++) {
        if (clients[i].fd == fd) {
            for (int j = i; j < client_count - 1; j++) {
                clients[j] = clients[j + 1];
            }
            client_count--;
            ESP_LOGI(TAG, "Client disconnected. Total clients: %d", client_count);
            break;
        }
    }
}

static websocket_client_t* get_client(int fd)
{
    for (int i = 0; i < client_count; i++) {
        if (clients[i].fd == fd) {
            return &clients[i];
        }
    }
    return NULL;
}

static esp_err_t websocket_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        ESP_LOGI(TAG, "WebSocket handshake");
        add_client(httpd_req_to_sockfd(req));
        return ESP_OK;
    }

    httpd_ws_frame_t ws_pkt;
    uint8_t *buf = NULL;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_recv_frame failed to get frame len with %d", ret);
        return ret;
    }

    if (ws_pkt.len) {
        buf = calloc(1, ws_pkt.len + 1);
        if (buf == NULL) {
            ESP_LOGE(TAG, "Failed to calloc memory for buf");
            return ESP_ERR_NO_MEM;
        }
        ws_pkt.payload = buf;
        ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "httpd_ws_recv_frame failed with %d", ret);
            free(buf);
            return ret;
        }
    }

    if (ws_pkt.type == HTTPD_WS_TYPE_TEXT) {
        int fd = httpd_req_to_sockfd(req);
        websocket_client_t *client = get_client(fd);
        
        if (client) {
            handle_websocket_message(client, (char*)ws_pkt.payload);
        }
    } else if (ws_pkt.type == HTTPD_WS_TYPE_CLOSE) {
        remove_client(httpd_req_to_sockfd(req));
    }

    if (buf) {
        free(buf);
    }
    return ESP_OK;
}

esp_err_t start_websocket_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_open_sockets = 13;

    ESP_LOGI(TAG, "Starting WebSocket server on port: '%d'", config.server_port);
    if (httpd_start(&websocket_server, &config) == ESP_OK) {
        httpd_uri_t ws = {
            .uri        = "/ws",
            .method     = HTTP_GET,
            .handler    = websocket_handler,
            .user_ctx   = NULL,
            .is_websocket = true
        };
        httpd_register_uri_handler(websocket_server, &ws);
        return ESP_OK;
    }

    ESP_LOGI(TAG, "Error starting WebSocket server!");
    return ESP_FAIL;
}

esp_err_t stop_websocket_server(void)
{
    if (websocket_server) {
        return httpd_stop(websocket_server);
    }
    return ESP_OK;
}