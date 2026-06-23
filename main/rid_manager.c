#include "rid_manager.h"
#include "rid_beacon.h"
#include "rid_wifi.h"
#include "rid_patrol.h"
#include "rid_config.h"
#include "rid_standard.h"
#include "rid_messages.h"
#include "rid_gb46750.h"


#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "RID_MGR";

// 链表头
static drone_instance_t *s_head = NULL;
static SemaphoreHandle_t s_mutex = NULL;
static uint32_t s_next_id = 1;
static TaskHandle_t s_dispatcher_task = NULL;

// ==================== 内部辅助函数 ====================

static void lock(void) {
    if (s_mutex) xSemaphoreTake(s_mutex, portMAX_DELAY);
}

static void unlock(void) {
    if (s_mutex) xSemaphoreGive(s_mutex);
}

static drone_instance_t* find_instance_unlocked(uint32_t id) {
    drone_instance_t *cur = s_head;
    while (cur) {
        if (cur->id == id) return cur;
        cur = cur->next;
    }
    return NULL;
}

// ==================== 公开 API ====================

esp_err_t rid_manager_init(void) {
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
        if (s_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create mutex");
            return ESP_ERR_NO_MEM;
        }
    }
    return ESP_OK;
}

esp_err_t rid_manager_create(rid_standard_t standard, const rid_config_t *init_config, uint32_t *out_id) {
    if (!init_config) return ESP_ERR_INVALID_ARG;
    if (rid_manager_init() != ESP_OK) return ESP_ERR_NO_MEM;

    drone_instance_t *inst = calloc(1, sizeof(drone_instance_t));
    if (!inst) return ESP_ERR_NO_MEM;

    inst->id = s_next_id++;
    inst->standard = standard;
    inst->active = false;
    inst->message_counter = 0;
    memcpy(&inst->config, init_config, sizeof(rid_config_t));

    lock();
    inst->next = s_head;
    s_head = inst;
    unlock();

    if (out_id) *out_id = inst->id;
    ESP_LOGD(TAG, "Created instance ID=%u, standard=%d", inst->id, standard);
    return ESP_OK;
}

esp_err_t rid_manager_delete(uint32_t id) {
    lock();
    drone_instance_t *prev = NULL, *cur = s_head;
    while (cur) {
        if (cur->id == id) {
            if (prev) prev->next = cur->next;
            else s_head = cur->next;
            free(cur);
            unlock();
            ESP_LOGI(TAG, "Deleted instance %u", id);
            return ESP_OK;
        }
        prev = cur;
        cur = cur->next;
    }
    unlock();
    return ESP_ERR_NOT_FOUND;
}

esp_err_t rid_manager_start(uint32_t id) {
    lock();
    drone_instance_t *inst = find_instance_unlocked(id);
    if (!inst) { unlock(); return ESP_ERR_NOT_FOUND; }
    if (inst->active) { unlock(); return ESP_OK; }
    inst->active = true;
    unlock();
    ESP_LOGI(TAG, "Started instance %u", id);
    return ESP_OK;
}

esp_err_t rid_manager_stop(uint32_t id) {
    lock();
    drone_instance_t *inst = find_instance_unlocked(id);
    if (!inst) { unlock(); return ESP_ERR_NOT_FOUND; }
    if (!inst->active) { unlock(); return ESP_OK; }
    inst->active = false;
    unlock();
    ESP_LOGI(TAG, "Stopped instance %u", id);
    return ESP_OK;
}

esp_err_t rid_manager_update_config(uint32_t id, const rid_config_t *new_config) {
    if (!new_config) return ESP_ERR_INVALID_ARG;
    lock();
    drone_instance_t *inst = find_instance_unlocked(id);
    if (!inst) { unlock(); return ESP_ERR_NOT_FOUND; }
    memcpy(&inst->config, new_config, sizeof(rid_config_t));
    unlock();
    ESP_LOGI(TAG, "Updated config for instance %u", id);
    return ESP_OK;
}

esp_err_t rid_manager_get_config(uint32_t id, rid_config_t *out_config) {
    if (!out_config) return ESP_ERR_INVALID_ARG;
    lock();
    drone_instance_t *inst = find_instance_unlocked(id);
    if (!inst) { unlock(); return ESP_ERR_NOT_FOUND; }
    memcpy(out_config, &inst->config, sizeof(rid_config_t));
    unlock();
    return ESP_OK;
}

drone_instance_t* rid_manager_find(uint32_t id) {
    lock();
    drone_instance_t *ret = find_instance_unlocked(id);
    unlock();
    return ret;
}

drone_instance_t* rid_manager_get_first(void) {
    lock();
    drone_instance_t *ret = s_head;
    unlock();
    return ret;
}

bool rid_manager_is_active(uint32_t id) {
    lock();
    drone_instance_t *inst = find_instance_unlocked(id);
    bool ret = inst ? inst->active : false;
    unlock();
    return ret;
}

rid_standard_t rid_manager_get_standard(uint32_t id) {
    lock();
    drone_instance_t *inst = find_instance_unlocked(id);
    rid_standard_t ret = inst ? inst->standard : RID_STANDARD_GB42590;
    unlock();
    return ret;
}

void rid_manager_clear_all(void) {
    lock();
    drone_instance_t *cur = s_head;
    while (cur) {
        drone_instance_t *next = cur->next;
        free(cur);
        cur = next;
    }
    s_head = NULL;
    unlock();
    ESP_LOGI(TAG, "Cleared all instances");
}

void rid_manager_for_each(instance_callback_t cb, void *user_ctx) {
    if (!cb) return;
    lock();
    drone_instance_t *cur = s_head;
    while (cur) {
        cb(cur, user_ctx);
        cur = cur->next;
    }
    unlock();
}

// ==================== NVS 持久化 ====================

// 持久化结构
typedef struct {
    uint32_t id;
    rid_standard_t standard;
    bool active;
    uint8_t message_counter;
    rid_config_t config;
} instance_persist_t;

#define INST_NVS_NAMESPACE "rid_inst"
#define INST_NVS_KEY "inst_list"

esp_err_t rid_manager_save_all(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(INST_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;

    lock();
    int count = 0;
    drone_instance_t *cur = s_head;
    while (cur) { count++; cur = cur->next; }

    if (count == 0) {
        nvs_erase_key(handle, INST_NVS_KEY);
        nvs_commit(handle);
        nvs_close(handle);
        unlock();
        return ESP_OK;
    }

    instance_persist_t *arr = malloc(count * sizeof(instance_persist_t));
    if (!arr) {
        nvs_close(handle);
        unlock();
        return ESP_ERR_NO_MEM;
    }

    cur = s_head;
    int idx = 0;
    while (cur) {
        arr[idx].id = cur->id;
        arr[idx].standard = cur->standard;
        arr[idx].active = cur->active;
        arr[idx].message_counter = cur->message_counter;
        memcpy(&arr[idx].config, &cur->config, sizeof(rid_config_t));
        idx++;
        cur = cur->next;
    }
    unlock();

    err = nvs_set_blob(handle, INST_NVS_KEY, arr, count * sizeof(instance_persist_t));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
        ESP_LOGI(TAG, "Saved %d instances to NVS", count);
    }
    free(arr);
    nvs_close(handle);
    return err;
}

esp_err_t rid_manager_load_all(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(INST_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;

    size_t blob_size = 0;
    err = nvs_get_blob(handle, INST_NVS_KEY, NULL, &blob_size);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        return ESP_ERR_NOT_FOUND;
    } else if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    if (blob_size == 0) {
        nvs_close(handle);
        return ESP_ERR_INVALID_SIZE;
    }

    instance_persist_t *arr = malloc(blob_size);
    if (!arr) {
        nvs_close(handle);
        return ESP_ERR_NO_MEM;
    }

    err = nvs_get_blob(handle, INST_NVS_KEY, arr, &blob_size);
    if (err != ESP_OK) {
        free(arr);
        nvs_close(handle);
        return err;
    }

    int count = blob_size / sizeof(instance_persist_t);
    if (count == 0) {
        free(arr);
        nvs_close(handle);
        return ESP_ERR_INVALID_SIZE;
    }

    // 清空现有实例
    rid_manager_clear_all();

    // 重建链表
    for (int i = 0; i < count; i++) {
        instance_persist_t *p = &arr[i];
        drone_instance_t *inst = malloc(sizeof(drone_instance_t));
        if (!inst) continue;
        inst->id = p->id;
        inst->standard = p->standard;
        inst->active = p->active;
        inst->message_counter = p->message_counter;
        memcpy(&inst->config, &p->config, sizeof(rid_config_t));
        // 头插法
        lock();
        inst->next = s_head;
        s_head = inst;
        unlock();
    }

    free(arr);
    nvs_close(handle);
    
    // 在加载循环结束后，打印所有实例
    lock();
    drone_instance_t *cur = s_head;
    while (cur) {
        ESP_LOGI(TAG, "Loaded instance: id=%u, active=%d, standard=%d", 
                 cur->id, cur->active, cur->standard);
        cur = cur->next;
    }
    unlock();
    return ESP_OK;
}

// ==================== 调度任务 ====================

static void dispatcher_task(void *arg) {
    ESP_LOGI(TAG, "Dispatcher task started");
    TickType_t last_wake = xTaskGetTickCount();
    uint32_t loop_cnt = 0;
    while (1) {
        vTaskDelayUntil(&last_wake, pdMS_TO_TICKS(1000));
        loop_cnt ++;
        ESP_LOGI(TAG, "Dispatcher loop %u", loop_cnt);

        lock();        
        drone_instance_t *cur = s_head;
        while (cur) {
            ESP_LOGD(TAG, "Instance %u: active=%d, standard=%d", cur->id, cur->active, cur->standard);
            if (cur->active) {
                // 计算位置（暂用全局）
                double lat, lon;
                float heading;
                //rid_patrol_calculate_next(&lat, &lon, &heading);
                rid_patrol_calculate_next_with_mode(cur->config.flight_mode, &lat, &lon, &heading);
                rid_config_update_position(&cur->config, (float)lat, (float)lon,
                                            cur->config.altitude_msl,
                                            cur->config.altitude_agl,
                                            cur->config.speed_horizontal,
                                            cur->config.speed_vertical,
                                            heading);

                
                const rid_standard_meta_t *meta = rid_get_standard_meta(cur->standard);
                if (meta == NULL) {
                    ESP_LOGE(TAG, "Instance %u: unknown standard", cur->id);
                    cur = cur->next;
                    continue;
                }
                ESP_LOGI(TAG, "Instance %u building frame, standard=%d", cur->id, cur->standard);
                
                // 构建 RID payload（打包后的数据）
                uint8_t payload[RID_MAX_PACK_MESSAGES * RID_SINGLE_MSG_SIZE + 3]; // 最大长度
                int payload_len = 0;
                if (meta->use_gb46750_encoder) {
                    // GB46750 直接编码
                    payload_len = rid_build_gb46750_payload(&cur->config, payload, sizeof(payload));
                } else {
                    // ASTM / GB42590：使用打包函数
                    payload_len = rid_pack_messages(payload, meta->pack_format, meta->builders, meta->msg_count, &cur->config);
                }
                if (payload_len > 0) {
                    esp_err_t ret = rid_wifi_set_rid_data(payload, payload_len, cur->message_counter);
                    if (ret == ESP_OK) {
                        cur->message_counter++;
                        ESP_LOGD(TAG, "Instance %u RID data updated", cur->id);
                    } else {
                        ESP_LOGE(TAG, "Instance %u set RID data failed: %s", cur->id, esp_err_to_name(ret));
                    }
                } else {
                    ESP_LOGE(TAG, "Instance %u payload build failed", cur->id);
                }
            }
            cur = cur->next;
        }
        unlock();
    }
}

void rid_manager_start_dispatcher(void) {
    if (s_dispatcher_task) return;
    xTaskCreate(dispatcher_task, "rid_dispatch", 4096, NULL, 5, &s_dispatcher_task);
    ESP_LOGI(TAG, "Dispatcher task created");
}