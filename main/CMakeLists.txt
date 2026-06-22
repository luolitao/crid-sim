idf_component_register(
    SRCS
        app_main.c
        rid_config.c
        rid_manager.c
        rid_packer.c
        rid_beacon.c
        rid_standard.c
        rid_messages.c
        rid_gb46750.c
        rid_messages_gb46750.c
        rid_patrol.c
        rid_standard.c
        rid_utils.c
        rid_wifi.c
        rid_ota.c
        rid_web_ota.c
    INCLUDE_DIRS "."
    REQUIRES
        esp_wifi
        driver
        esp_driver_uart
        app_update
        esp_https_ota
        esp_http_client
        esp_http_server
        nvs_flash
        esp_common
        esp_netif
        esp_event
        esp_timer
    PRIV_REQUIRES soc)

target_link_libraries(${COMPONENT_LIB} m)
