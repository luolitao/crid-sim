#ifndef RID_UTILS_H
#define RID_UTILS_H

#include <stdint.h>
#include <stdbool.h>

void write_le16(uint8_t *buf, uint16_t val);
void write_le32(uint8_t *buf, int32_t val);
void write_le32_u32(uint8_t *buf, uint32_t val);

int32_t encode_lat_lon(double deg, bool is_lat);
uint16_t encode_altitude(float m);
uint8_t encode_speed_h(float ms);
int8_t encode_speed_v(float ms);
uint8_t encode_direction(float deg, bool *is_west);
uint16_t encode_timestamp(float sec);

#endif // RID_UTILS_H