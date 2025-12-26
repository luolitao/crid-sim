idf_component_register(SRCS  crid.c
                       INCLUDE_DIRS ""
                       REQUIRES esp_wifi nvs_flash esp_wifi esp_common esp_netif esp_event
                    PRIV_REQUIRES soc)

target_link_libraries(${COMPONENT_LIB} m)                