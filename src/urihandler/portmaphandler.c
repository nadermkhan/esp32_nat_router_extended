#include "handler.h"
#include "lwip/ip_addr.h"

static const char *TAG = "PortMapHandler";

// Enhanced validation functions
static bool validate_port_range(int port) {
    return port >= 1 && port <= 65535;
}

static bool validate_protocol(const char *protocol) {
    return protocol && (strcasecmp(protocol, "tcp") == 0 || strcasecmp(protocol, "udp") == 0);
}

static bool is_reserved_port(int port) {
    // Common reserved/system ports that should not be forwarded
    int reserved_ports[] = {22, 23, 53, 67, 68, 80, 443, 993, 995};
    int num_reserved = sizeof(reserved_ports) / sizeof(reserved_ports[0]);
    
    for (int i = 0; i < num_reserved; i++) {
        if (port == reserved_ports[i]) {
            return true;
        }
    }
    return false;
}

static bool port_mapping_exists(uint8_t proto, uint16_t ext_port, uint32_t int_ip, uint16_t int_port) {
    for (int i = 0; i < PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid && 
            portmap_tab[i].proto == proto && 
            portmap_tab[i].mport == ext_port) {
            return true;
        }
    }
    return false;
}

esp_err_t api_portmap_get_handler(httpd_req_t *req) {
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
    cJSON *entries_array = cJSON_CreateArray();
    cJSON *statistics = cJSON_CreateObject();

    int active_mappings = 0;
    int tcp_mappings = 0;
    int udp_mappings = 0;

    for (int i = 0; i < PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
            cJSON *entry = cJSON_CreateObject();
            
            const char *protocol = (portmap_tab[i].proto == PROTO_TCP) ? "TCP" : "UDP";
            cJSON_AddStringToObject(entry, "protocol", protocol);
            cJSON_AddNumberToObject(entry, "externalPort", portmap_tab[i].mport);
            
            esp_ip4_addr_t addr;
            addr.addr = portmap_tab[i].daddr;
            char ip_str[16];
            esp_ip4addr_ntoa(&addr, ip_str, sizeof(ip_str));
            cJSON_AddStringToObject(entry, "internalIP", ip_str);
            cJSON_AddNumberToObject(entry, "internalPort", portmap_tab[i].dport);
            
            // Create unique ID for deletion
            char id[64];
            snprintf(id, sizeof(id), "%s_%hu_%s_%hu", 
                    protocol, portmap_tab[i].mport, ip_str, portmap_tab[i].dport);
            cJSON_AddStringToObject(entry, "id", id);
            
            // Add status information
            cJSON_AddBoolToObject(entry, "active", true);
            cJSON_AddNumberToObject(entry, "index", i);
            
            // Check if it's a reserved port
            cJSON_AddBoolToObject(entry, "isReserved", is_reserved_port(portmap_tab[i].mport));
            
            cJSON_AddItemToArray(entries_array, entry);
            
            active_mappings++;
            if (portmap_tab[i].proto == PROTO_TCP) tcp_mappings++;
            else udp_mappings++;
        }
    }

    cJSON_AddItemToObject(data, "entries", entries_array);
    
    // Add statistics
    cJSON_AddNumberToObject(statistics, "total", active_mappings);
    cJSON_AddNumberToObject(statistics, "tcp", tcp_mappings);
    cJSON_AddNumberToObject(statistics, "udp", udp_mappings);
    cJSON_AddNumberToObject(statistics, "available", PORTMAP_MAX - active_mappings);
    cJSON_AddNumberToObject(statistics, "maxEntries", PORTMAP_MAX);
    cJSON_AddItemToObject(data, "statistics", statistics);
    
    // Add network information
    cJSON *network = cJSON_CreateObject();
    char *default_ip = getDefaultIPByNetmask();
    if (default_ip) {
        char ip_prefix[16];
        strncpy(ip_prefix, default_ip, strlen(default_ip) - 1);
        ip_prefix[strlen(default_ip) - 1] = '\0';
        cJSON_AddStringToObject(network, "ipPrefix", ip_prefix);
        cJSON_AddStringToObject(network, "gatewayIP", default_ip);
        free(default_ip);
    }
    cJSON_AddItemToObject(data, "network", network);

    api_response_t response = {
        .success = true,
        .message = "Port mapping information retrieved successfully",
        .data = data,
        .status_code = 200
    };

    ESP_LOGI(TAG, "Retrieved %d port mappings", active_mappings);
    return send_api_response(req, &response);
}

esp_err_t api_portmap_post_handler(httpd_req_t *req) {
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

    char buf[req->content_len + 1];
    if (fill_post_buffer(req, buf, req->content_len) != ESP_OK) {
        api_response_t response = {
            .success = false,
            .message = "Failed to read request data",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }
    buf[req->content_len] = '\0';

    char func_param[8] = {0};
    readUrlParameterIntoBuffer(buf, "func", func_param, sizeof(func_param));
    sanitize_string_input(func_param, sizeof(func_param));

    if (strlen(func_param) == 0) {
        api_response_t response = {
            .success = false,
            .message = "Function parameter is required",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }

    cJSON *data = cJSON_CreateObject();

    if (strcmp(func_param, "add") == 0) {
        // Add port mapping
        char protocol[8] = {0}, ext_port_str[8] = {0};
        char ip_suffix[8] = {0}, int_port_str[8] = {0};
        char description[64] = {0};

        readUrlParameterIntoBuffer(buf, "protocol", protocol, sizeof(protocol));
        readUrlParameterIntoBuffer(buf, "eport", ext_port_str, sizeof(ext_port_str));
        readUrlParameterIntoBuffer(buf, "ip", ip_suffix, sizeof(ip_suffix));
        readUrlParameterIntoBuffer(buf, "iport", int_port_str, sizeof(int_port_str));
        readUrlParameterIntoBuffer(buf, "description", description, sizeof(description));

        // Sanitize inputs
        sanitize_string_input(protocol, sizeof(protocol));
        sanitize_string_input(ext_port_str, sizeof(ext_port_str));
        sanitize_string_input(ip_suffix, sizeof(ip_suffix));
        sanitize_string_input(int_port_str, sizeof(int_port_str));
        sanitize_string_input(description, sizeof(description));

        // Validate protocol
        if (!validate_protocol(protocol)) {
            api_response_t response = {
                .success = false,
                .message = "Invalid protocol (must be TCP or UDP)",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        uint8_t proto = (strcasecmp(protocol, "tcp") == 0) ? PROTO_TCP : PROTO_UDP;

        // Validate and parse external port
        if (strlen(ext_port_str) == 0) {
            api_response_t response = {
                .success = false,
                .message = "External port is required",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        char *endptr;
        long ext_port_long = strtol(ext_port_str, &endptr, 10);
        if (*endptr != '\0' || !validate_port_range(ext_port_long)) {
            api_response_t response = {
                .success = false,
                .message = "Invalid external port (must be 1-65535)",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        uint16_t ext_port = (uint16_t)ext_port_long;

        // Check for reserved ports
        if (is_reserved_port(ext_port)) {
            cJSON *warning = cJSON_CreateObject();
            cJSON_AddBoolToObject(warning, "isReservedPort", true);
            cJSON_AddStringToObject(warning, "warningMessage", 
                "Warning: This is a reserved system port. Mapping may interfere with system services.");
            cJSON_AddItemToObject(data, "warning", warning);
        }

        // Validate and construct internal IP
        if (strlen(ip_suffix) == 0) {
            api_response_t response = {
                .success = false,
                .message = "IP suffix is required",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        char *default_ip = getDefaultIPByNetmask();
        if (!default_ip) {
            api_response_t response = {
                .success = false,
                .message = "Failed to get network configuration",
                .status_code = 500
            };
            return send_api_response(req, &response);
        }

        char full_ip[32];
        snprintf(full_ip, sizeof(full_ip), "%.*s%s", 
                (int)(strlen(default_ip) - 1), default_ip, ip_suffix);
        free(default_ip);

        if (!is_valid_ip_address(full_ip)) {
            api_response_t response = {
                .success = false,
                .message = "Invalid internal IP address",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        uint32_t int_ip = esp_ip4addr_aton(full_ip);
        if (int_ip == IPADDR_NONE) {
            api_response_t response = {
                .success = false,
                .message = "Invalid internal IP address format",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        // Validate and parse internal port
        if (strlen(int_port_str) == 0) {
            api_response_t response = {
                .success = false,
                .message = "Internal port is required",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        long int_port_long = strtol(int_port_str, &endptr, 10);
        if (*endptr != '\0' || !validate_port_range(int_port_long)) {
            api_response_t response = {
                .success = false,
                .message = "Invalid internal port (must be 1-65535)",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        uint16_t int_port = (uint16_t)int_port_long;

        // Check if mapping already exists
        if (port_mapping_exists(proto, ext_port, int_ip, int_port)) {
            api_response_t response = {
                .success = false,
                .message = "Port mapping already exists",
                .status_code = 409
            };
            return send_api_response(req, &response);
        }

        // Add the port mapping
        esp_err_t add_result = add_portmap(proto, ext_port, int_ip, int_port);
        if (add_result != ESP_OK) {
            const char *error_msg = "Failed to add port mapping";
            if (add_result == ESP_ERR_NO_MEM) {
                error_msg = "Maximum number of port mappings reached";
            }
            
            api_response_t response = {
                .success = false,
                .message = error_msg,
                .status_code = 507
            };
            return send_api_response(req, &response);
        }

        // Success response
        cJSON_AddStringToObject(data, "action", "add");
        cJSON_AddStringToObject(data, "protocol", protocol);
        cJSON_AddNumberToObject(data, "externalPort", ext_port);
        cJSON_AddStringToObject(data, "internalIP", full_ip);
        cJSON_AddNumberToObject(data, "internalPort", int_port);
        if (strlen(description) > 0) {
            cJSON_AddStringToObject(data, "description", description);
        }

        api_response_t response = {
            .success = true,
            .message = "Port mapping added successfully",
            .data = data,
            .status_code = 200
        };

        ESP_LOGI(TAG, "Added port mapping: %s:%d -> %s:%d (%s)", 
                 "", ext_port, full_ip, int_port, protocol);
        return send_api_response(req, &response);

    } else if (strcmp(func_param, "del") == 0) {
        // Delete port mapping
        char entry_id[128] = {0};
        readUrlParameterIntoBuffer(buf, "entry", entry_id, sizeof(entry_id));
        sanitize_string_input(entry_id, sizeof(entry_id));

        if (strlen(entry_id) == 0) {
            api_response_t response = {
                .success = false,
                .message = "Entry ID is required for deletion",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        // Parse entry ID: "TCP_80_192.168.1.100_8080"
        char *token = strtok(entry_id, "_");
        if (!token) {
            api_response_t response = {
                .success = false,
                .message = "Invalid entry ID format",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        uint8_t proto = (strcmp(token, "TCP") == 0) ? PROTO_TCP : PROTO_UDP;

        token = strtok(NULL, "_");
        if (!token) {
            api_response_t response = {
                .success = false,
                .message = "Invalid entry ID format - missing external port",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        char *endptr;
        long ext_port_long = strtol(token, &endptr, 10);
        if (*endptr != '\0' || !validate_port_range(ext_port_long)) {
            api_response_t response = {
                .success = false,
                .message = "Invalid external port in entry ID",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }
        uint16_t ext_port = (uint16_t)ext_port_long;

        token = strtok(NULL, "_");
        if (!token) {
            api_response_t response = {
                .success = false,
                .message = "Invalid entry ID format - missing internal IP",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        if (!is_valid_ip_address(token)) {
            api_response_t response = {
                .success = false,
                .message = "Invalid internal IP in entry ID",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        uint32_t int_ip = esp_ip4addr_aton(token);

        token = strtok(NULL, "_");
        if (!token) {
            api_response_t response = {
                .success = false,
                .message = "Invalid entry ID format - missing internal port",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }

        long int_port_long = strtol(token, &endptr, 10);
        if (*endptr != '\0' || !validate_port_range(int_port_long)) {
            api_response_t response = {
                .success = false,
                .message = "Invalid internal port in entry ID",
                .status_code = 400
            };
            return send_api_response(req, &response);
        }
        uint16_t int_port = (uint16_t)int_port_long;

        // Delete the port mapping
        esp_err_t del_result = del_portmap(proto, ext_port, int_ip, int_port);
        if (del_result != ESP_OK) {
            api_response_t response = {
                .success = false,
                .message = "Port mapping not found or failed to delete",
                .status_code = 404
            };
            return send_api_response(req, &response);
        }

        // Success response
        cJSON_AddStringToObject(data, "action", "delete");
        cJSON_AddStringToObject(data, "deletedEntry", entry_id);
        cJSON_AddStringToObject(data, "protocol", (proto == PROTO_TCP) ? "TCP" : "UDP");
        cJSON_AddNumberToObject(data, "externalPort", ext_port);
        cJSON_AddNumberToObject(data, "internalPort", int_port);

        api_response_t response = {
            .success = true,
            .message = "Port mapping deleted successfully",
            .data = data,
            .status_code = 200
        };

        ESP_LOGI(TAG, "Deleted port mapping: %s:%d -> %d (%s)", 
                 "", ext_port, int_port, (proto == PROTO_TCP) ? "TCP" : "UDP");
        return send_api_response(req, &response);

    } else if (strcmp(func_param, "clear") == 0) {
        // Clear all port mappings
        int cleared_count = 0;
        for (int i = 0; i < PORTMAP_MAX; i++) {
            if (portmap_tab[i].valid) {
                portmap_tab[i].valid = 0;
                cleared_count++;
            }
        }

        cJSON_AddStringToObject(data, "action", "clear");
        cJSON_AddNumberToObject(data, "clearedCount", cleared_count);

        api_response_t response = {
            .success = true,
            .message = "All port mappings cleared successfully",
            .data = data,
            .status_code = 200
        };

        ESP_LOGI(TAG, "Cleared %d port mappings", cleared_count);
        return send_api_response(req, &response);

    } else {
        api_response_t response = {
            .success = false,
            .message = "Invalid function parameter (must be 'add', 'del', or 'clear')",
            .status_code = 400
        };
        return send_api_response(req, &response);
    }
}