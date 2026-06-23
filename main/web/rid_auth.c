#include "rid_auth.h"
#include <string.h>
#include <ctype.h>

// ================= Base64 解码（轻量级） =================
static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_size) {
    size_t out_pos = 0;
    int bits = 0, buffer = 0;
    for (size_t i = 0; i < in_len && out_pos < out_size; i++) {
        char c = in[i];
        if (c == '=') break;
        int val = base64_decode_char(c);
        if (val < 0) continue;
        buffer = (buffer << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[out_pos++] = (buffer >> bits) & 0xFF;
        }
    }
    return out_pos;
}



// ==================== HTTP 基本认证 ====================
#define WEB_USERNAME "admin"
#define WEB_PASSWORD "password"


bool validate_auth(httpd_req_t *req) {
    char auth_buf[256];
    size_t auth_len = sizeof(auth_buf);
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_buf, auth_len) != ESP_OK) {
        return false;
    }
    const char *auth_header = auth_buf;
    if (strncasecmp(auth_header, "Basic ", 6) != 0) return false;
    auth_header += 6;
    uint8_t decoded[64];
    size_t decoded_len = base64_decode(auth_header, strlen(auth_header), decoded, sizeof(decoded));
    if (decoded_len == 0) return false;
    decoded[decoded_len] = '\0';
    char *sep = strchr((char*)decoded, ':');
    if (!sep) return false;
    *sep = '\0';
    char *user = (char*)decoded;
    char *pass = (char*)(sep + 1);
    return (strcmp(user, WEB_USERNAME) == 0 && strcmp(pass, WEB_PASSWORD) == 0);
}