idf_component_register(SRCS
        app_main.c
        core/rid_beacon.c
        core/rid_messages.c
        core/rid_gb46750.c
        core/rid_standard.c
        core/rid_utils.c
        core/rid_patrol.c
        manager/rid_manager.c
        manager/rid_config.c
        network/rid_wifi.c
        network/rid_ota.c
        web/rid_web_ota.c
        web/rid_api.c
        web/rid_auth.c
        web/rid_static.c
        cli/crid_cli.c
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

# 添加包含路径（相对于 main）
target_include_directories(${COMPONENT_TARGET} PRIVATE
    "core"
    "manager"
    "network"
    "web"
    "cli"
    "."
)
target_link_libraries(${COMPONENT_LIB} m)

# 添加测试组件
if(CONFIG_ESP_UNITY_ENABLE)
    target_link_libraries(${COMPONENT_LIB} PRIVATE unity)
endif()