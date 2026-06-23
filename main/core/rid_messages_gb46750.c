// rid_messages_gb46750.c
#include "rid_messages.h"
#include "rid_gb46750.h"

int rid_build_gb46750_payload(const rid_config_t *config, uint8_t *out, size_t max_len) {
    if (!config || !out) return -1;

    gb46750_data_t data;
    gb46750_from_config(config, &data);

    return gb46750_encode(&data, out, max_len);
}