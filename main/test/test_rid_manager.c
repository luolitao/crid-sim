#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "rid_manager.h"
#include "rid_config.h"

// 测试前初始化
static void setUp(void) {
    rid_manager_clear_all();
    rid_manager_init();
}

static void tearDown(void) {
    rid_manager_clear_all();
}

// 测试：创建实例
void test_create_instance(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    strcpy(cfg.uas_id, "TEST-001");
    cfg.latitude = 23.0;
    cfg.longitude = 113.0;

    uint32_t id;
    esp_err_t ret = rid_manager_create(RID_STANDARD_GB42590, &cfg, &id);
    TEST_ASSERT_EQUAL(ESP_OK, ret);
    TEST_ASSERT_NOT_EQUAL(0, id);

    // 验证实例存在
    drone_instance_t *inst = rid_manager_find(id);
    TEST_ASSERT_NOT_NULL(inst);
    TEST_ASSERT_EQUAL_STRING("TEST-001", inst->config.uas_id);
    TEST_ASSERT_EQUAL(23.0, inst->config.latitude);
    TEST_ASSERT_EQUAL(113.0, inst->config.longitude);
    TEST_ASSERT_EQUAL(false, inst->active);
}

// 测试：重复 UAS ID 检查
void test_create_duplicate_uid(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    strcpy(cfg.uas_id, "TEST-001");
    uint32_t id1, id2;
    esp_err_t ret1 = rid_manager_create(RID_STANDARD_GB42590, &cfg, &id1);
    TEST_ASSERT_EQUAL(ESP_OK, ret1);

    esp_err_t ret2 = rid_manager_create(RID_STANDARD_GB42590, &cfg, &id2);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, ret2);  // 假设返回此错误
}

// 测试：启动和停止
void test_start_stop(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    uint32_t id;
    rid_manager_create(RID_STANDARD_GB42590, &cfg, &id);

    esp_err_t ret = rid_manager_start(id);
    TEST_ASSERT_EQUAL(ESP_OK, ret);
    TEST_ASSERT_TRUE(rid_manager_is_active(id));

    ret = rid_manager_stop(id);
    TEST_ASSERT_EQUAL(ESP_OK, ret);
    TEST_ASSERT_FALSE(rid_manager_is_active(id));
}

// 测试：删除实例
void test_delete_instance(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    uint32_t id;
    rid_manager_create(RID_STANDARD_GB42590, &cfg, &id);

    esp_err_t ret = rid_manager_delete(id);
    TEST_ASSERT_EQUAL(ESP_OK, ret);
    TEST_ASSERT_NULL(rid_manager_find(id));
}

// 测试：更新配置
void test_update_config(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    strcpy(cfg.uas_id, "OLD-ID");
    uint32_t id;
    rid_manager_create(RID_STANDARD_GB42590, &cfg, &id);

    rid_config_t new_cfg;
    rid_config_init_default(&new_cfg);
    strcpy(new_cfg.uas_id, "NEW-ID");
    new_cfg.latitude = 31.0;
    new_cfg.longitude = 121.0;

    esp_err_t ret = rid_manager_update_config(id, &new_cfg);
    TEST_ASSERT_EQUAL(ESP_OK, ret);

    rid_config_t got;
    rid_manager_get_config(id, &got);
    TEST_ASSERT_EQUAL_STRING("NEW-ID", got.uas_id);
    TEST_ASSERT_EQUAL(31.0, got.latitude);
    TEST_ASSERT_EQUAL(121.0, got.longitude);
}