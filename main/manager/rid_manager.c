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
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>

#define INST_NVS_NAMESPACE "rid_inst"
#define INST_NVS_KEY "inst_list"

static const char *TAG = "RID_MGR";

static SemaphoreHandle_t s_mutex = NULL;
static uint32_t s_next_id = 1;
static TaskHandle_t s_dispatcher_task = NULL;
// 链表头
static drone_instance_t *s_head = NULL;
static drone_instance_t *s_current_instance = NULL;  // 当前正在广播的实例

// 持久化结构
typedef struct {
    uint32_t id;
    rid_standard_t standard;
    bool active;
    uint8_t message_counter;
    rid_config_t config;
} instance_persist_t;

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
    // 检查 UAS ID 是否重复
    lock();
    
    drone_instance_t *cur = s_head;
    while (cur) {
        if (strncmp(cur->config.uas_id, init_config->uas_id, RID_UAS_ID_MAX_LEN) == 0) {
            unlock();
            return ESP_ERR_INVALID_ARG; // 或其他自定义错误
        }
        cur = cur->next;
    }
    unlock();
    // 继续创建...

    inst->id = s_next_id++;
    inst->standard = standard;
    inst->active = false;
    inst->message_counter = 0;
    memcpy(&inst->config, init_config, sizeof(rid_config_t));

    lock();
    inst->next = s_head;
    s_head = inst;
    unlock();
    // 从 config 生成 patrol_params
    rid_patrol_params_from_mode(init_config->flight_mode, init_config, &inst->patrol_params);
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
    // 停止所有其他实例
    drone_instance_t *cur = s_head;
    while (cur) {
        if (cur != inst && cur->active) {
            cur->active = false;
        }
        cur = cur->next;
    }
    inst->active = true;
    s_current_instance = inst;
    unlock();
    ESP_LOGI(TAG, "Started instance %u, stopped others", id);
    return ESP_OK;
}

esp_err_t rid_manager_stop(uint32_t id) {
    lock();
    drone_instance_t *inst = find_instance_unlocked(id);
    if (!inst) { unlock(); return ESP_ERR_NOT_FOUND; }
    inst->active = false;
    if (s_current_instance == inst) {
        s_current_instance = NULL;
    }
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
    // 更新轨迹参数
    rid_patrol_params_from_mode(new_config->flight_mode, new_config, &inst->patrol_params);
    unlock();
    ESP_LOGI(TAG, "Updated config and patrol params for instance %u", id);
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

esp_err_t rid_manager_update_standard(uint32_t id, rid_standard_t standard) {
    lock();
    drone_instance_t *inst = find_instance_unlocked(id);
    if (!inst) {
        unlock();
        return ESP_ERR_NOT_FOUND;
    }
    inst->standard = standard;
    unlock();
    ESP_LOGI(TAG, "Updated standard for instance %u to %d", id, standard);
    return ESP_OK;
}


// ==================== NVS 持久化 ====================
esp_err_t rid_manager_save_all(void) {
    lock();
    if (s_head == NULL) {
        unlock();
        ESP_LOGI(TAG, "No instances to save");
        return ESP_OK;
    }
    int count = 0;
    drone_instance_t *cur = s_head;
    while (cur) { count++; cur = cur->next; }

    instance_persist_t *arr = malloc(count * sizeof(instance_persist_t));
    if (!arr) {
        unlock();
        ESP_LOGE(TAG, "malloc failed");
        return ESP_ERR_NO_MEM;
    }

    cur = s_head;
    int idx = 0;
    while (cur && idx < count) {
        arr[idx].id = cur->id;
        arr[idx].standard = cur->standard;
        arr[idx].active = cur->active;
        arr[idx].message_counter = cur->message_counter;
        memcpy(&arr[idx].config, &cur->config, sizeof(rid_config_t));
        idx++;
        cur = cur->next;
    }
    unlock();

    if (idx != count) {
        ESP_LOGE(TAG, "Instance count mismatch");
        free(arr);
        return ESP_ERR_INVALID_STATE;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(INST_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        free(arr);
        return err;
    }
    err = nvs_set_blob(handle, INST_NVS_KEY, arr, count * sizeof(instance_persist_t));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
        ESP_LOGI(TAG, "Saved %d instances", count);
    } else {
        ESP_LOGE(TAG, "nvs_set_blob failed: %s", esp_err_to_name(err));
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
        return ESP_ERR_NOT_FOUND;  // 不清理链表，保留现有
    } else if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    // 读取成功，清空并重建
    rid_manager_clear_all();

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
    for (int i = 0; i < count; i++) {
        instance_persist_t *p = &arr[i];
        drone_instance_t *inst = malloc(sizeof(drone_instance_t));
        if (!inst) continue;
        inst->id = p->id;
        inst->standard = p->standard;
        inst->active = p->active;
        inst->message_counter = p->message_counter;
        memcpy(&inst->config, &p->config, sizeof(rid_config_t));
        // 重建 patrol_params
        rid_patrol_params_from_mode(inst->config.flight_mode, &inst->config, &inst->patrol_params);
        lock();
        inst->next = s_head;
        s_head = inst;
        unlock();
        if (p->id > s_next_id) s_next_id = p->id + 1;
    }
    free(arr);
    nvs_close(handle);
    return ESP_OK;
}

#include "freertos/queue.h"

static QueueHandle_t s_ie_queue = NULL;
#define IE_QUEUE_LEN 10

typedef struct {
    uint8_t payload[256];
    size_t len;
    uint8_t counter;
} ie_update_msg_t;

// 独立任务：从队列取数据并调用 rid_wifi_set_rid_data
static void ie_updater_task(void *arg) {
    ie_update_msg_t msg;
    while (1) {
        if (xQueueReceive(s_ie_queue, &msg, portMAX_DELAY) == pdTRUE) {
            rid_wifi_set_rid_data(msg.payload, msg.len, msg.counter);
        }
    }
}

static void dispatcher_task(void *arg) {
    ESP_LOGI(TAG, "Dispatcher task started");
    TickType_t last_wake = xTaskGetTickCount();
    while (1) {
        vTaskDelayUntil(&last_wake, pdMS_TO_TICKS(1000));

        // 查找活跃实例
        lock();
        drone_instance_t *inst = s_current_instance;        
        unlock();
       
        if (inst && inst->active) {
            // 计算位置
            double lat, lon;
            float heading;
            double time_sec = (double)esp_timer_get_time() / 1e6;
            rid_patrol_calculate(&inst->patrol_params, time_sec, &lat, &lon, &heading);
            // 更新配置中的位置
            rid_config_update_position(&inst->config, (float)lat, (float)lon,
                                        inst->config.altitude_msl,
                                        inst->config.altitude_agl,
                                        inst->config.speed_horizontal,
                                        inst->config.speed_vertical,
                                        heading);

            const rid_standard_meta_t *meta = rid_get_standard_meta(inst->standard);
            if (meta) {
                uint8_t payload[256];
                int payload_len = 0;
                if (meta->msg_count == 0) {
                    payload_len = rid_build_gb46750_payload(&inst->config, payload, sizeof(payload));
                } else {
                    payload_len = rid_pack_messages(payload, meta, &inst->config);
                }
                if (payload_len > 0) {
                    ie_update_msg_t msg;
                    msg.len = payload_len;
                    msg.counter = inst->message_counter;
                    memcpy(msg.payload, payload, payload_len);

                    if (xQueueSend(s_ie_queue, &msg, 0) == pdTRUE) {
                        inst->message_counter++;
                        ESP_LOGD(TAG, "Instance %u RID data queued", inst->id);
                    } else {
                        ESP_LOGW(TAG, "IE queue full, dropping update for instance %u", inst->id);
                    }
                }
            }
        }
    }
}

// 启动队列和更新任务
void rid_manager_start_dispatcher(void) {
    if (s_dispatcher_task) return;
    if (s_ie_queue == NULL) {
        s_ie_queue = xQueueCreate(IE_QUEUE_LEN, sizeof(ie_update_msg_t));
        xTaskCreate(ie_updater_task, "ie_updater", 2048, NULL, 1, NULL); // 最低优先级
    }
    xTaskCreate(dispatcher_task, "rid_dispatch", 4096, NULL, 2, &s_dispatcher_task);
    ESP_LOGI(TAG, "Dispatcher and updater tasks created");
}
