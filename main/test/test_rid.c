#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "rid_config.h"
#include "rid_manager.h"
#include "rid_messages.h"
#include "rid_standard.h"
#include "rid_utils.h"

// 测试前准备
void setUp(void) {
    // 这里可以做一些初始化，比如清空实例链表
    rid_manager_clear_all();
}

void tearDown(void) {
    // 清理资源
}

// 测试用例：创建单个实例
void test_rid_manager_create(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    strcpy(cfg.uas_id, "TEST-DRONE-001");
    cfg.latitude = 23.0f;
    cfg.longitude = 113.0f;

    uint32_t id;
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_create(RID_STANDARD_GB42590, &cfg, &id));
    TEST_ASSERT_NOT_EQUAL(0, id);

    // 验证实例存在且配置正确
    rid_config_t read_cfg;
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_get_config(id, &read_cfg));
    TEST_ASSERT_EQUAL_STRING("TEST-DRONE-001", read_cfg.uas_id);
}

// 测试用例：UAS ID 重复检测
void test_rid_manager_duplicate_uas_id(void) {
    rid_config_t cfg1, cfg2;
    rid_config_init_default(&cfg1);
    rid_config_init_default(&cfg2);
    strcpy(cfg1.uas_id, "DUPLICATE-ID");
    strcpy(cfg2.uas_id, "DUPLICATE-ID");
    
    uint32_t id1, id2;
    TEST_ASSERT_EQUAL(ESP_OK, rid_manager_create(RID_STANDARD_GB42590, &cfg1, &id1));
    // 第二次创建应失败
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, rid_manager_create(RID_STANDARD_GB42590, &cfg2, &id2));
}

// 测试用例：消息打包（验证头部格式）
void test_rid_pack_messages(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    cfg.latitude = 23.14287f;
    cfg.longitude = 113.26026f;

    const rid_standard_meta_t *meta = rid_get_standard_meta(RID_STANDARD_GB42590);
    TEST_ASSERT_NOT_NULL(meta);

    uint8_t payload[128];
    int len = rid_pack_messages(payload, meta->pack_format, meta->builders, meta->msg_count, &cfg);
    TEST_ASSERT_GREATER_THAN(0, len);

    // 检查头部：GB42590 格式为 0xF1, 0x19, 0x03
    if (meta->pack_format == PACK_FORMAT_GB42590) {
        TEST_ASSERT_EQUAL(0xF1, payload[0]);
        TEST_ASSERT_EQUAL(0x19, payload[1]);  // 25 字节
        TEST_ASSERT_EQUAL(0x03, payload[2]);  // 3 条消息
    } else if (meta->pack_format == PACK_FORMAT_ASTM) {
        TEST_ASSERT_EQUAL(0xF1, payload[0]);
        TEST_ASSERT_EQUAL(0x03, payload[1]);
    }
}

// 测试用例：NVS 持久化（需要物理 Flash，可选）
void test_rid_manager_nvs_save_load(void) {
    // 注意：此测试需要真实 NVS，且会擦除数据，建议仅在模拟环境下运行
    // 或者使用 nvs_flash_erase 模拟。
}

// 运行所有测试
void app_main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_rid_manager_create);
    RUN_TEST(test_rid_manager_duplicate_uas_id);
    RUN_TEST(test_rid_pack_messages);
    // 如果有依赖硬件的测试，可以跳过或只在特定条件下运行
    UNITY_END();
}