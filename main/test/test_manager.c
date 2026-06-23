#include "unity.h"
#include "rid_manager.h"
#include "rid_config.h"
#include <string.h>

// 测试前初始化
static void setUp(void) {
    rid_manager_init();
    rid_manager_clear_all();  // 清空所有实例
}

// 测试后清理
static void tearDown(void) {
    rid_manager_clear_all();
}

// 测试用例1：创建实例，ID 自增
void test_create_instance_id_increment(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    strcpy(cfg.uas_id, "TEST001");

    uint32_t id1, id2;
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_create(RID_STANDARD_GB42590, &cfg, &id1));
    TEST_ASSERT_EQUAL(1, id1);
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_create(RID_STANDARD_GB42590, &cfg, &id2)); // 相同 UAS ID 会失败
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, id2); // 应该失败
}

// 测试用例2：UAS ID 唯一性
void test_uas_id_uniqueness(void) {
    rid_config_t cfg1, cfg2;
    rid_config_init_default(&cfg1);
    rid_config_init_default(&cfg2);
    strcpy(cfg1.uas_id, "UNIQUE1");
    strcpy(cfg2.uas_id, "UNIQUE1"); // 重复

    uint32_t id1, id2;
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_create(RID_STANDARD_GB42590, &cfg1, &id1));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, rid_manager_create(RID_STANDARD_GB42590, &cfg2, &id2));
}

// 测试用例3：更新配置
void test_update_config(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    strcpy(cfg.uas_id, "UPDATETEST");
    cfg.latitude = 10.0;
    cfg.longitude = 20.0;

    uint32_t id;
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_create(RID_STANDARD_GB42590, &cfg, &id));

    rid_config_t new_cfg;
    rid_config_init_default(&new_cfg);
    strcpy(new_cfg.uas_id, "UPDATED");
    new_cfg.latitude = 30.0;
    new_cfg.longitude = 40.0;

    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_update_config(id, &new_cfg));

    rid_config_t retrieved;
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_get_config(id, &retrieved));
    TEST_ASSERT_EQUAL_STRING("UPDATED", retrieved.uas_id);
    TEST_ASSERT_EQUAL(30.0, retrieved.latitude);
    TEST_ASSERT_EQUAL(40.0, retrieved.longitude);
}

// 测试用例4：启动/停止实例
void test_start_stop(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    strcpy(cfg.uas_id, "STARTSTOP");

    uint32_t id;
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_create(RID_STANDARD_GB42590, &cfg, &id));
    TEST_ASSERT_FALSE(rid_manager_is_active(id));

    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_start(id));
    TEST_ASSERT_TRUE(rid_manager_is_active(id));

    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_stop(id));
    TEST_ASSERT_FALSE(rid_manager_is_active(id));
}

// 测试用例5：删除实例
void test_delete_instance(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    strcpy(cfg.uas_id, "DELETE");

    uint32_t id;
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_create(RID_STANDARD_GB42590, &cfg, &id));
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_delete(id));
    TEST_ASSERT_EQUAL(ESP_ERR_NOT_FOUND, rid_manager_delete(id)); // 二次删除应失败
}

// 测试用例6：NVS 持久化（模拟）
void test_persistence(void) {
    // 注意：真实 NVS 需要硬件，此处先跳过，但可以模拟。
    // 若需测试，可调用 rid_manager_save_all 和 rid_manager_load_all
    // 因依赖实际 Flash，可在集成测试阶段进行。
    TEST_IGNORE_MESSAGE("NVS test requires hardware, skip");
}

// 更新标准
void test_update_standard(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    strcpy(cfg.uas_id, "STDTEST");
    uint32_t id;
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_create(RID_STANDARD_GB42590, &cfg, &id));
    // 通过更新 config 改变 standard（需要 standard 在 config 中）
    // 假设 rid_config_t 有 standard 字段
    cfg.standard = RID_STANDARD_ASTM;
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_update_config(id, &cfg));
    rid_config_t retrieved;
    rid_manager_get_config(id, &retrieved);
    TEST_ASSERT_EQUAL(RID_STANDARD_ASTM, retrieved.standard);
}

// 测试运行函数
void app_main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_create_instance_id_increment);
    RUN_TEST(test_uas_id_uniqueness);
    RUN_TEST(test_update_config);
    RUN_TEST(test_start_stop);
    RUN_TEST(test_delete_instance);
    RUN_TEST(test_persistence);
    RUN_TEST(test_update_standard);
    UNITY_END();
}