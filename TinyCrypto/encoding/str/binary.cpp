#include "binary.h"
#include <assert.h>

namespace tc {

static const char U8ARRAY_TO_BIN_MAP[256][8] = {
    {'0', '0', '0', '0', '0', '0', '0', '0'}, //  0
    {'0', '0', '0', '0', '0', '0', '0', '1'}, //  1
    {'0', '0', '0', '0', '0', '0', '1', '0'}, //  2
    {'0', '0', '0', '0', '0', '0', '1', '1'}, //  3
    {'0', '0', '0', '0', '0', '1', '0', '0'}, //  4
    {'0', '0', '0', '0', '0', '1', '0', '1'}, //  5
    {'0', '0', '0', '0', '0', '1', '1', '0'}, //  6
    {'0', '0', '0', '0', '0', '1', '1', '1'}, //  7
    {'0', '0', '0', '0', '1', '0', '0', '0'}, //  8
    {'0', '0', '0', '0', '1', '0', '0', '1'}, //  9
    {'0', '0', '0', '0', '1', '0', '1', '0'}, //  10
    {'0', '0', '0', '0', '1', '0', '1', '1'}, //  11
    {'0', '0', '0', '0', '1', '1', '0', '0'}, //  12
    {'0', '0', '0', '0', '1', '1', '0', '1'}, //  13
    {'0', '0', '0', '0', '1', '1', '1', '0'}, //  14
    {'0', '0', '0', '0', '1', '1', '1', '1'}, //  15
    {'0', '0', '0', '1', '0', '0', '0', '0'}, //  16
    {'0', '0', '0', '1', '0', '0', '0', '1'}, //  17
    {'0', '0', '0', '1', '0', '0', '1', '0'}, //  18
    {'0', '0', '0', '1', '0', '0', '1', '1'}, //  19
    {'0', '0', '0', '1', '0', '1', '0', '0'}, //  20
    {'0', '0', '0', '1', '0', '1', '0', '1'}, //  21
    {'0', '0', '0', '1', '0', '1', '1', '0'}, //  22
    {'0', '0', '0', '1', '0', '1', '1', '1'}, //  23
    {'0', '0', '0', '1', '1', '0', '0', '0'}, //  24
    {'0', '0', '0', '1', '1', '0', '0', '1'}, //  25
    {'0', '0', '0', '1', '1', '0', '1', '0'}, //  26
    {'0', '0', '0', '1', '1', '0', '1', '1'}, //  27
    {'0', '0', '0', '1', '1', '1', '0', '0'}, //  28
    {'0', '0', '0', '1', '1', '1', '0', '1'}, //  29
    {'0', '0', '0', '1', '1', '1', '1', '0'}, //  30
    {'0', '0', '0', '1', '1', '1', '1', '1'}, //  31
    {'0', '0', '1', '0', '0', '0', '0', '0'}, //  32
    {'0', '0', '1', '0', '0', '0', '0', '1'}, //  33
    {'0', '0', '1', '0', '0', '0', '1', '0'}, //  34
    {'0', '0', '1', '0', '0', '0', '1', '1'}, //  35
    {'0', '0', '1', '0', '0', '1', '0', '0'}, //  36
    {'0', '0', '1', '0', '0', '1', '0', '1'}, //  37
    {'0', '0', '1', '0', '0', '1', '1', '0'}, //  38
    {'0', '0', '1', '0', '0', '1', '1', '1'}, //  39
    {'0', '0', '1', '0', '1', '0', '0', '0'}, //  40
    {'0', '0', '1', '0', '1', '0', '0', '1'}, //  41
    {'0', '0', '1', '0', '1', '0', '1', '0'}, //  42
    {'0', '0', '1', '0', '1', '0', '1', '1'}, //  43
    {'0', '0', '1', '0', '1', '1', '0', '0'}, //  44
    {'0', '0', '1', '0', '1', '1', '0', '1'}, //  45
    {'0', '0', '1', '0', '1', '1', '1', '0'}, //  46
    {'0', '0', '1', '0', '1', '1', '1', '1'}, //  47
    {'0', '0', '1', '1', '0', '0', '0', '0'}, //  48
    {'0', '0', '1', '1', '0', '0', '0', '1'}, //  49
    {'0', '0', '1', '1', '0', '0', '1', '0'}, //  50
    {'0', '0', '1', '1', '0', '0', '1', '1'}, //  51
    {'0', '0', '1', '1', '0', '1', '0', '0'}, //  52
    {'0', '0', '1', '1', '0', '1', '0', '1'}, //  53
    {'0', '0', '1', '1', '0', '1', '1', '0'}, //  54
    {'0', '0', '1', '1', '0', '1', '1', '1'}, //  55
    {'0', '0', '1', '1', '1', '0', '0', '0'}, //  56
    {'0', '0', '1', '1', '1', '0', '0', '1'}, //  57
    {'0', '0', '1', '1', '1', '0', '1', '0'}, //  58
    {'0', '0', '1', '1', '1', '0', '1', '1'}, //  59
    {'0', '0', '1', '1', '1', '1', '0', '0'}, //  60
    {'0', '0', '1', '1', '1', '1', '0', '1'}, //  61
    {'0', '0', '1', '1', '1', '1', '1', '0'}, //  62
    {'0', '0', '1', '1', '1', '1', '1', '1'}, //  63
    {'0', '1', '0', '0', '0', '0', '0', '0'}, //  64
    {'0', '1', '0', '0', '0', '0', '0', '1'}, //  65
    {'0', '1', '0', '0', '0', '0', '1', '0'}, //  66
    {'0', '1', '0', '0', '0', '0', '1', '1'}, //  67
    {'0', '1', '0', '0', '0', '1', '0', '0'}, //  68
    {'0', '1', '0', '0', '0', '1', '0', '1'}, //  69
    {'0', '1', '0', '0', '0', '1', '1', '0'}, //  70
    {'0', '1', '0', '0', '0', '1', '1', '1'}, //  71
    {'0', '1', '0', '0', '1', '0', '0', '0'}, //  72
    {'0', '1', '0', '0', '1', '0', '0', '1'}, //  73
    {'0', '1', '0', '0', '1', '0', '1', '0'}, //  74
    {'0', '1', '0', '0', '1', '0', '1', '1'}, //  75
    {'0', '1', '0', '0', '1', '1', '0', '0'}, //  76
    {'0', '1', '0', '0', '1', '1', '0', '1'}, //  77
    {'0', '1', '0', '0', '1', '1', '1', '0'}, //  78
    {'0', '1', '0', '0', '1', '1', '1', '1'}, //  79
    {'0', '1', '0', '1', '0', '0', '0', '0'}, //  80
    {'0', '1', '0', '1', '0', '0', '0', '1'}, //  81
    {'0', '1', '0', '1', '0', '0', '1', '0'}, //  82
    {'0', '1', '0', '1', '0', '0', '1', '1'}, //  83
    {'0', '1', '0', '1', '0', '1', '0', '0'}, //  84
    {'0', '1', '0', '1', '0', '1', '0', '1'}, //  85
    {'0', '1', '0', '1', '0', '1', '1', '0'}, //  86
    {'0', '1', '0', '1', '0', '1', '1', '1'}, //  87
    {'0', '1', '0', '1', '1', '0', '0', '0'}, //  88
    {'0', '1', '0', '1', '1', '0', '0', '1'}, //  89
    {'0', '1', '0', '1', '1', '0', '1', '0'}, //  90
    {'0', '1', '0', '1', '1', '0', '1', '1'}, //  91
    {'0', '1', '0', '1', '1', '1', '0', '0'}, //  92
    {'0', '1', '0', '1', '1', '1', '0', '1'}, //  93
    {'0', '1', '0', '1', '1', '1', '1', '0'}, //  94
    {'0', '1', '0', '1', '1', '1', '1', '1'}, //  95
    {'0', '1', '1', '0', '0', '0', '0', '0'}, //  96
    {'0', '1', '1', '0', '0', '0', '0', '1'}, //  97
    {'0', '1', '1', '0', '0', '0', '1', '0'}, //  98
    {'0', '1', '1', '0', '0', '0', '1', '1'}, //  99
    {'0', '1', '1', '0', '0', '1', '0', '0'}, //  100
    {'0', '1', '1', '0', '0', '1', '0', '1'}, //  101
    {'0', '1', '1', '0', '0', '1', '1', '0'}, //  102
    {'0', '1', '1', '0', '0', '1', '1', '1'}, //  103
    {'0', '1', '1', '0', '1', '0', '0', '0'}, //  104
    {'0', '1', '1', '0', '1', '0', '0', '1'}, //  105
    {'0', '1', '1', '0', '1', '0', '1', '0'}, //  106
    {'0', '1', '1', '0', '1', '0', '1', '1'}, //  107
    {'0', '1', '1', '0', '1', '1', '0', '0'}, //  108
    {'0', '1', '1', '0', '1', '1', '0', '1'}, //  109
    {'0', '1', '1', '0', '1', '1', '1', '0'}, //  110
    {'0', '1', '1', '0', '1', '1', '1', '1'}, //  111
    {'0', '1', '1', '1', '0', '0', '0', '0'}, //  112
    {'0', '1', '1', '1', '0', '0', '0', '1'}, //  113
    {'0', '1', '1', '1', '0', '0', '1', '0'}, //  114
    {'0', '1', '1', '1', '0', '0', '1', '1'}, //  115
    {'0', '1', '1', '1', '0', '1', '0', '0'}, //  116
    {'0', '1', '1', '1', '0', '1', '0', '1'}, //  117
    {'0', '1', '1', '1', '0', '1', '1', '0'}, //  118
    {'0', '1', '1', '1', '0', '1', '1', '1'}, //  119
    {'0', '1', '1', '1', '1', '0', '0', '0'}, //  120
    {'0', '1', '1', '1', '1', '0', '0', '1'}, //  121
    {'0', '1', '1', '1', '1', '0', '1', '0'}, //  122
    {'0', '1', '1', '1', '1', '0', '1', '1'}, //  123
    {'0', '1', '1', '1', '1', '1', '0', '0'}, //  124
    {'0', '1', '1', '1', '1', '1', '0', '1'}, //  125
    {'0', '1', '1', '1', '1', '1', '1', '0'}, //  126
    {'0', '1', '1', '1', '1', '1', '1', '1'}, //  127
    {'1', '0', '0', '0', '0', '0', '0', '0'}, //  128
    {'1', '0', '0', '0', '0', '0', '0', '1'}, //  129
    {'1', '0', '0', '0', '0', '0', '1', '0'}, //  130
    {'1', '0', '0', '0', '0', '0', '1', '1'}, //  131
    {'1', '0', '0', '0', '0', '1', '0', '0'}, //  132
    {'1', '0', '0', '0', '0', '1', '0', '1'}, //  133
    {'1', '0', '0', '0', '0', '1', '1', '0'}, //  134
    {'1', '0', '0', '0', '0', '1', '1', '1'}, //  135
    {'1', '0', '0', '0', '1', '0', '0', '0'}, //  136
    {'1', '0', '0', '0', '1', '0', '0', '1'}, //  137
    {'1', '0', '0', '0', '1', '0', '1', '0'}, //  138
    {'1', '0', '0', '0', '1', '0', '1', '1'}, //  139
    {'1', '0', '0', '0', '1', '1', '0', '0'}, //  140
    {'1', '0', '0', '0', '1', '1', '0', '1'}, //  141
    {'1', '0', '0', '0', '1', '1', '1', '0'}, //  142
    {'1', '0', '0', '0', '1', '1', '1', '1'}, //  143
    {'1', '0', '0', '1', '0', '0', '0', '0'}, //  144
    {'1', '0', '0', '1', '0', '0', '0', '1'}, //  145
    {'1', '0', '0', '1', '0', '0', '1', '0'}, //  146
    {'1', '0', '0', '1', '0', '0', '1', '1'}, //  147
    {'1', '0', '0', '1', '0', '1', '0', '0'}, //  148
    {'1', '0', '0', '1', '0', '1', '0', '1'}, //  149
    {'1', '0', '0', '1', '0', '1', '1', '0'}, //  150
    {'1', '0', '0', '1', '0', '1', '1', '1'}, //  151
    {'1', '0', '0', '1', '1', '0', '0', '0'}, //  152
    {'1', '0', '0', '1', '1', '0', '0', '1'}, //  153
    {'1', '0', '0', '1', '1', '0', '1', '0'}, //  154
    {'1', '0', '0', '1', '1', '0', '1', '1'}, //  155
    {'1', '0', '0', '1', '1', '1', '0', '0'}, //  156
    {'1', '0', '0', '1', '1', '1', '0', '1'}, //  157
    {'1', '0', '0', '1', '1', '1', '1', '0'}, //  158
    {'1', '0', '0', '1', '1', '1', '1', '1'}, //  159
    {'1', '0', '1', '0', '0', '0', '0', '0'}, //  160
    {'1', '0', '1', '0', '0', '0', '0', '1'}, //  161
    {'1', '0', '1', '0', '0', '0', '1', '0'}, //  162
    {'1', '0', '1', '0', '0', '0', '1', '1'}, //  163
    {'1', '0', '1', '0', '0', '1', '0', '0'}, //  164
    {'1', '0', '1', '0', '0', '1', '0', '1'}, //  165
    {'1', '0', '1', '0', '0', '1', '1', '0'}, //  166
    {'1', '0', '1', '0', '0', '1', '1', '1'}, //  167
    {'1', '0', '1', '0', '1', '0', '0', '0'}, //  168
    {'1', '0', '1', '0', '1', '0', '0', '1'}, //  169
    {'1', '0', '1', '0', '1', '0', '1', '0'}, //  170
    {'1', '0', '1', '0', '1', '0', '1', '1'}, //  171
    {'1', '0', '1', '0', '1', '1', '0', '0'}, //  172
    {'1', '0', '1', '0', '1', '1', '0', '1'}, //  173
    {'1', '0', '1', '0', '1', '1', '1', '0'}, //  174
    {'1', '0', '1', '0', '1', '1', '1', '1'}, //  175
    {'1', '0', '1', '1', '0', '0', '0', '0'}, //  176
    {'1', '0', '1', '1', '0', '0', '0', '1'}, //  177
    {'1', '0', '1', '1', '0', '0', '1', '0'}, //  178
    {'1', '0', '1', '1', '0', '0', '1', '1'}, //  179
    {'1', '0', '1', '1', '0', '1', '0', '0'}, //  180
    {'1', '0', '1', '1', '0', '1', '0', '1'}, //  181
    {'1', '0', '1', '1', '0', '1', '1', '0'}, //  182
    {'1', '0', '1', '1', '0', '1', '1', '1'}, //  183
    {'1', '0', '1', '1', '1', '0', '0', '0'}, //  184
    {'1', '0', '1', '1', '1', '0', '0', '1'}, //  185
    {'1', '0', '1', '1', '1', '0', '1', '0'}, //  186
    {'1', '0', '1', '1', '1', '0', '1', '1'}, //  187
    {'1', '0', '1', '1', '1', '1', '0', '0'}, //  188
    {'1', '0', '1', '1', '1', '1', '0', '1'}, //  189
    {'1', '0', '1', '1', '1', '1', '1', '0'}, //  190
    {'1', '0', '1', '1', '1', '1', '1', '1'}, //  191
    {'1', '1', '0', '0', '0', '0', '0', '0'}, //  192
    {'1', '1', '0', '0', '0', '0', '0', '1'}, //  193
    {'1', '1', '0', '0', '0', '0', '1', '0'}, //  194
    {'1', '1', '0', '0', '0', '0', '1', '1'}, //  195
    {'1', '1', '0', '0', '0', '1', '0', '0'}, //  196
    {'1', '1', '0', '0', '0', '1', '0', '1'}, //  197
    {'1', '1', '0', '0', '0', '1', '1', '0'}, //  198
    {'1', '1', '0', '0', '0', '1', '1', '1'}, //  199
    {'1', '1', '0', '0', '1', '0', '0', '0'}, //  200
    {'1', '1', '0', '0', '1', '0', '0', '1'}, //  201
    {'1', '1', '0', '0', '1', '0', '1', '0'}, //  202
    {'1', '1', '0', '0', '1', '0', '1', '1'}, //  203
    {'1', '1', '0', '0', '1', '1', '0', '0'}, //  204
    {'1', '1', '0', '0', '1', '1', '0', '1'}, //  205
    {'1', '1', '0', '0', '1', '1', '1', '0'}, //  206
    {'1', '1', '0', '0', '1', '1', '1', '1'}, //  207
    {'1', '1', '0', '1', '0', '0', '0', '0'}, //  208
    {'1', '1', '0', '1', '0', '0', '0', '1'}, //  209
    {'1', '1', '0', '1', '0', '0', '1', '0'}, //  210
    {'1', '1', '0', '1', '0', '0', '1', '1'}, //  211
    {'1', '1', '0', '1', '0', '1', '0', '0'}, //  212
    {'1', '1', '0', '1', '0', '1', '0', '1'}, //  213
    {'1', '1', '0', '1', '0', '1', '1', '0'}, //  214
    {'1', '1', '0', '1', '0', '1', '1', '1'}, //  215
    {'1', '1', '0', '1', '1', '0', '0', '0'}, //  216
    {'1', '1', '0', '1', '1', '0', '0', '1'}, //  217
    {'1', '1', '0', '1', '1', '0', '1', '0'}, //  218
    {'1', '1', '0', '1', '1', '0', '1', '1'}, //  219
    {'1', '1', '0', '1', '1', '1', '0', '0'}, //  220
    {'1', '1', '0', '1', '1', '1', '0', '1'}, //  221
    {'1', '1', '0', '1', '1', '1', '1', '0'}, //  222
    {'1', '1', '0', '1', '1', '1', '1', '1'}, //  223
    {'1', '1', '1', '0', '0', '0', '0', '0'}, //  224
    {'1', '1', '1', '0', '0', '0', '0', '1'}, //  225
    {'1', '1', '1', '0', '0', '0', '1', '0'}, //  226
    {'1', '1', '1', '0', '0', '0', '1', '1'}, //  227
    {'1', '1', '1', '0', '0', '1', '0', '0'}, //  228
    {'1', '1', '1', '0', '0', '1', '0', '1'}, //  229
    {'1', '1', '1', '0', '0', '1', '1', '0'}, //  230
    {'1', '1', '1', '0', '0', '1', '1', '1'}, //  231
    {'1', '1', '1', '0', '1', '0', '0', '0'}, //  232
    {'1', '1', '1', '0', '1', '0', '0', '1'}, //  233
    {'1', '1', '1', '0', '1', '0', '1', '0'}, //  234
    {'1', '1', '1', '0', '1', '0', '1', '1'}, //  235
    {'1', '1', '1', '0', '1', '1', '0', '0'}, //  236
    {'1', '1', '1', '0', '1', '1', '0', '1'}, //  237
    {'1', '1', '1', '0', '1', '1', '1', '0'}, //  238
    {'1', '1', '1', '0', '1', '1', '1', '1'}, //  239
    {'1', '1', '1', '1', '0', '0', '0', '0'}, //  240
    {'1', '1', '1', '1', '0', '0', '0', '1'}, //  241
    {'1', '1', '1', '1', '0', '0', '1', '0'}, //  242
    {'1', '1', '1', '1', '0', '0', '1', '1'}, //  243
    {'1', '1', '1', '1', '0', '1', '0', '0'}, //  244
    {'1', '1', '1', '1', '0', '1', '0', '1'}, //  245
    {'1', '1', '1', '1', '0', '1', '1', '0'}, //  246
    {'1', '1', '1', '1', '0', '1', '1', '1'}, //  247
    {'1', '1', '1', '1', '1', '0', '0', '0'}, //  248
    {'1', '1', '1', '1', '1', '0', '0', '1'}, //  249
    {'1', '1', '1', '1', '1', '0', '1', '0'}, //  250
    {'1', '1', '1', '1', '1', '0', '1', '1'}, //  251
    {'1', '1', '1', '1', '1', '1', '0', '0'}, //  252
    {'1', '1', '1', '1', '1', '1', '0', '1'}, //  253
    {'1', '1', '1', '1', '1', '1', '1', '0'}, //  254
    {'1', '1', '1', '1', '1', '1', '1', '1'}, //  255
};

#define memcpy8(dst, src) ((uint64_t*)(dst))[0] = ((uint64_t*)(src))[0]

void u8array_to_bin(char* out, const uint8_t* in, size_t inl)
{
    while (inl)
    {
        memcpy8(out, U8ARRAY_TO_BIN_MAP[*in]);
        out += 8, inl -= 1, in += 1;
    }
    *out = '\0';
}

void uint8_to_bin(char out[9], uint8_t in)
{
    memcpy8(out, U8ARRAY_TO_BIN_MAP[in]);
    out[8] = '\0';
}

void uint16_to_bin(char out[17], uint16_t in)
{
    memcpy8(out + 0, U8ARRAY_TO_BIN_MAP[(in >> 8) & 0xFF]);
    memcpy8(out + 8, U8ARRAY_TO_BIN_MAP[(in >> 0) & 0xFF]);
    out[16] = '\0';
}

void uint32_to_bin(char out[33], uint32_t in)
{
    memcpy8(out + 0, U8ARRAY_TO_BIN_MAP[(in >> 24) & 0xFF]);
    memcpy8(out + 8, U8ARRAY_TO_BIN_MAP[(in >> 16) & 0xFF]);
    memcpy8(out + 16, U8ARRAY_TO_BIN_MAP[(in >> 8) & 0xFF]);
    memcpy8(out + 24, U8ARRAY_TO_BIN_MAP[(in >> 0) & 0xFF]);
    out[32] = '\0';
}

void uint64_to_bin(char out[65], uint64_t in)
{
    memcpy8(out + 0, U8ARRAY_TO_BIN_MAP[(in >> 56) & 0xFF]);
    memcpy8(out + 8, U8ARRAY_TO_BIN_MAP[(in >> 48) & 0xFF]);
    memcpy8(out + 16, U8ARRAY_TO_BIN_MAP[(in >> 40) & 0xFF]);
    memcpy8(out + 24, U8ARRAY_TO_BIN_MAP[(in >> 32) & 0xFF]);
    memcpy8(out + 32, U8ARRAY_TO_BIN_MAP[(in >> 24) & 0xFF]);
    memcpy8(out + 40, U8ARRAY_TO_BIN_MAP[(in >> 16) & 0xFF]);
    memcpy8(out + 48, U8ARRAY_TO_BIN_MAP[(in >> 8) & 0xFF]);
    memcpy8(out + 56, U8ARRAY_TO_BIN_MAP[(in >> 0) & 0xFF]);
    out[64] = '\0';
}

static int bin_check(const char* in, size_t inl)
{
    if (inl % 8 != 0)
    {
        return -1;
    }
    for (size_t i = 0; i < inl; i++)
    {
        if (!(in[i] == '0' || in[i] == '1'))
        {
            return -1;
        }
    }
    return 0;
}

int bin_to_u8array(uint8_t* out, const char* in, size_t inl)
{
    if (bin_check(in, inl))
    {
        return -1;
    }
    while (inl)
    {
        *out = bin_to_uint8_f(in);
        out += 1, in += 8, inl -= 8;
    }
    return 0;
}

int bin_to_uint8(uint8_t* out, const char in[8])
{
    if (bin_check(in, 8))
    {
        return -1;
    }
    *out = bin_to_uint8_f(in);
    return 0;
}

int bin_to_uint16(uint16_t* out, const char in[16])
{
    if (bin_check(in, 16))
    {
        return -1;
    }
    *out = bin_to_uint16_f(in);
    return 0;
}

int bin_to_uint32(uint32_t* out, const char in[32])
{
    if (bin_check(in, 32))
    {
        return -1;
    }
    *out = bin_to_uint32_f(in);
    return 0;
}

int bin_to_uint64(uint64_t* out, const char in[64])
{
    if (bin_check(in, 64))
    {
        return -1;
    }
    *out = bin_to_uint64_f(in);
    return 0;
}

uint8_t bin_to_uint8_f(const char in[8])
{
    return (uint8_t)(in[0] - '0') << 7 | (uint8_t)(in[1] - '0') << 6 |
           (uint8_t)(in[2] - '0') << 5 | (uint8_t)(in[3] - '0') << 4 |
           (uint8_t)(in[4] - '0') << 3 | (uint8_t)(in[5] - '0') << 2 |
           (uint8_t)(in[6] - '0') << 1 | (uint8_t)(in[7] - '0');
}

uint16_t bin_to_uint16_f(const char in[16])
{
    return (uint16_t)bin_to_uint8_f(in + 0) << 8 |
           (uint16_t)bin_to_uint8_f(in + 8);
}

uint32_t bin_to_uint32_f(const char in[32])
{
    return (uint32_t)bin_to_uint8_f(in + 0) << 24 |
           (uint32_t)bin_to_uint8_f(in + 8) << 16 |
           (uint32_t)bin_to_uint8_f(in + 16) << 8 |
           (uint32_t)bin_to_uint8_f(in + 24);
}

uint64_t bin_to_uint64_f(const char in[64])
{
    return (uint64_t)bin_to_uint32_f(in + 0) << 32 |
           (uint64_t)bin_to_uint32_f(in + 32);
}

}; // namespace tc