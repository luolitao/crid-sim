#ifndef RID_MANAGER_H
#define RID_MANAGER_H

#include "rid_config.h"
#include "rid_standard.h"
#include "rid_patrol.h"
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

// 无人机实例结构（公开定义）
// 可以在 drone_instance_t 中添加 patrol_params 字段
typedef struct drone_instance {
    uint32_t id;
    rid_standard_t standard;
    rid_config_t config;
    uint8_t message_counter;
    bool active;
    patrol_params_t patrol_params;   // 新增：轨迹参数
    struct drone_instance *next;
} drone_instance_t;


// ==================== 管理 API ====================

/**
 * @brief 初始化实例管理器（创建互斥锁）
 */
esp_err_t rid_manager_init(void);

/**
 * @brief 创建新实例（默认不启动）
 * @param standard 标准类型
 * @param init_config 初始配置（复制）
 * @param out_id 返回实例 ID
 */
esp_err_t rid_manager_create(rid_standard_t standard, const rid_config_t *init_config, uint32_t *out_id);

/**
 * @brief 删除实例
 */
esp_err_t rid_manager_delete(uint32_t id);

/**
 * @brief 启动实例（开始发送 Beacon）
 */
esp_err_t rid_manager_start(uint32_t id);

/**
 * @brief 停止实例
 */
esp_err_t rid_manager_stop(uint32_t id);

/**
 * @brief 更新实例配置（完全替换）
 */
esp_err_t rid_manager_update_config(uint32_t id, const rid_config_t *new_config);

/**
 * @brief 获取实例配置副本
 */
esp_err_t rid_manager_get_config(uint32_t id, rid_config_t *out_config);

/**
 * @brief 查找实例（返回指针，仅用于临时访问，不可长期持有）
 */
drone_instance_t* rid_manager_find(uint32_t id);

/**
 * @brief 获取第一个实例（简化用）
 */
drone_instance_t* rid_manager_get_first(void);

/**
 * @brief 检查实例是否活跃
 */
bool rid_manager_is_active(uint32_t id);

/**
 * @brief 获取实例标准类型
 */
rid_standard_t rid_manager_get_standard(uint32_t id);

/**
 * @brief 更新实例的标准
 * @param id 实例 ID
 * @param standard 新的标准
 * @return ESP_OK 成功，ESP_ERR_NOT_FOUND 实例不存在
 */
esp_err_t rid_manager_update_standard(uint32_t id, rid_standard_t standard);

// ==================== NVS 持久化 ====================

/**
 * @brief 保存所有实例到 NVS
 */
esp_err_t rid_manager_save_all(void);

/**
 * @brief 从 NVS 加载所有实例（会清空当前链表）
 */
esp_err_t rid_manager_load_all(void);

/**
 * @brief 清空所有实例（用于加载前）
 */
void rid_manager_clear_all(void);

// ==================== 调度器 ====================
/**
 * @brief 启动调度任务（1Hz 轮询所有活跃实例并发送 Beacon）
 */
void rid_manager_start_dispatcher(void);

// 可选：遍历所有实例的回调
typedef void (*instance_callback_t)(drone_instance_t *inst, void *user_ctx);
void rid_manager_for_each(instance_callback_t cb, void *user_ctx);

#endif // RID_MANAGER_H