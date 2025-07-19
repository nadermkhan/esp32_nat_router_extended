#ifndef WEBSOCKET_HANDLERS_H
#define WEBSOCKET_HANDLERS_H

#include "websocket_server.h"
#include <stdbool.h>

void handle_websocket_message(websocket_client_t *client, const char *message);

#endif