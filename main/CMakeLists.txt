idf_component_register(
    SRCS
        crid-sim.c
        crid_config.c
        crid_cli.c
        crid_ota.c
        crid_web_ota.c
        crid_messages.c
        crid_wifi.c
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
    PRIV_REQUIRES soc)

target_link_libraries(${COMPONENT_LIB} m)
