#ifndef WEBSOCKET_SERVER_H
#define WEBSOCKET_SERVER_H

#include "esp_http_server.h"
#include "cJSON.h"
#include <stdbool.h>

typedef struct {
    httpd_handle_t server;
    int fd;
    bool authenticated;
} websocket_client_t;

esp_err_t start_websocket_server(void);
esp_err_t stop_websocket_server(void);
esp_err_t websocket_send_json(int fd, cJSON *json);
esp_err_t websocket_broadcast_json(cJSON *json);

#endif