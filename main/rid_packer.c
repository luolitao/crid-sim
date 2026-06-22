#include "rid_messages.h"
#include <string.h>

int rid_pack_messages(uint8_t *out, pack_format_t format,
                      const msg_builder_t builders[], uint8_t count,
                      const rid_config_t *config) {
    if (!out || !builders || count == 0 || count > RID_MAX_PACK_MESSAGES) return -1;
    
    uint8_t temp[RID_MAX_PACK_MESSAGES][RID_SINGLE_MSG_SIZE];
    int pos = 0;
    
    // 写入头部
    if (format == PACK_FORMAT_ASTM) {
        out[pos++] = (RID_MSG_PACK << 4) | RID_PROTOCOL_VERSION; // 0xF1
        out[pos++] = count;
    } else { // GB42590
        out[pos++] = 0xF1;
        out[pos++] = RID_SINGLE_MSG_SIZE;
        out[pos++] = count;
    }
    
    // 编码每条消息
    for (int i = 0; i < count; i++) {
        builders[i](config, temp[i]);
        memcpy(out + pos, temp[i], RID_SINGLE_MSG_SIZE);
        pos += RID_SINGLE_MSG_SIZE;
    }
    return pos;
}