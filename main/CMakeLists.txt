idf_component_register(
    SRCS
        main.c
        rid_config.c
        rid_ota.c
        rid_web_ota.c
        encode_gb42590.c
        rid_wifi.c
        crid_patrol.c
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
