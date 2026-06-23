#include <string.h>
#include "unity.h"
#include "rid_messages.h"
#include "rid_standard.h"

void test_pack_messages_astm(void) {
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    // 模拟一些数据
    strcpy(cfg.uas_id, "TEST-001");
    cfg.latitude = 23.14287;
    cfg.longitude = 113.26026;
    cfg.altitude_msl = 50.0f;

    const msg_builder_t builders[] = {
        rid_encode_basic_id,
        rid_encode_location,
        rid_encode_system
    };
    uint8_t out[128];
    int len = rid_pack_messages(out, PACK_FORMAT_ASTM, builders, 3, &cfg);
    TEST_ASSERT_GREATER_THAN(0, len);

    // 检查头部
    TEST_ASSERT_EQUAL(0xF1, out[0]);
    TEST_ASSERT_EQUAL(3, out[1]);

    // 可以进一步检查第一条消息的类型
    TEST_ASSERT_EQUAL(0x11, out[2]);  // Basic ID 消息头
}