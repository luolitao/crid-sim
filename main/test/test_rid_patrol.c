#include <math.h>
#include "unity.h"
#include "rid_patrol.h"

void test_patrol_circle(void) {
    double lat = 23.14287;
    double lon = 113.26026;
    float heading = 0.0;
    // 这里假设您实现了带参数版本，我们调用：
    rid_patrol_calculate_next_with_mode(FLIGHT_MODE_CIRCLE, &lat, &lon, &heading);
    // 验证位置变化在预期范围内
    TEST_ASSERT_FLOAT_WITHIN(0.001, 23.142879, lat);
    TEST_ASSERT_FLOAT_WITHIN(0.001, 113.260757, lon);
    TEST_ASSERT_FLOAT_WITHIN(1.0, 91.1, heading);
}

void test_patrol_pingpong(void) {
    // 类似测试
}