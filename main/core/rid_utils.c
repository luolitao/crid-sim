#include "rid_utils.h"
#include <math.h>
#include <string.h>

void write_le16(uint8_t *buf, uint16_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
}

void write_le32(uint8_t *buf, int32_t val) {
    uint32_t u = (uint32_t)val;
    buf[0] = u & 0xFF;
    buf[1] = (u >> 8) & 0xFF;
    buf[2] = (u >> 16) & 0xFF;
    buf[3] = (u >> 24) & 0xFF;
}

void write_le32_u32(uint8_t *buf, uint32_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF;
    buf[3] = (val >> 24) & 0xFF;
}

uint8_t encode_direction(float deg, bool *is_west) {
    if (deg < 0.0f || deg >= 360.0f) {
        if (is_west) *is_west = false;
        return 255; // Invalid
    }
    uint16_t dir = (uint16_t)roundf(deg);
    if (dir >= 360) dir -= 360;
    if (dir >= 180) {
        if (is_west) *is_west = true;
        return (uint8_t)(dir - 180);
    } else {
        if (is_west) *is_west = false;
        return (uint8_t)dir;
    }
}

uint8_t encode_speed_h(float ms) {
    if (ms < 0.0f || ms > 254.25f) return 255;
    return (uint8_t)roundf(ms * 4.0f);
}

int8_t encode_speed_v(float ms) {
    if (ms < -31.75f || ms > 31.75f) return 127;
    return (int8_t)roundf(ms * 4.0f);
}

int32_t encode_lat_lon(double deg, bool is_lat) {
    if (deg == 0.0) return 0;
    double limit = is_lat ? 90.0 : 180.0;
    if (deg < -limit || deg > limit) return 0;
    return (int32_t)round(deg * 1e7);
}

uint16_t encode_altitude(float m) {
    if (m <= -1000.0f) return 0xFFFF;
    if (m >= 11000.0f) return 0xFFFE;
    float val = (m + 1000.0f) * 2.0f;
    if (val < 0.0f) val = 0.0f;
    if (val > 65535.0f) val = 65535.0f;
    return (uint16_t)roundf(val);
}

uint16_t encode_timestamp(float sec) {
    if (sec >= 3600.0f || sec < 0.0f) return 0xFFFF;
    return (uint16_t)roundf(sec * 10.0f);
}