#include "matcher.h"

static uint8_t fold(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32u) : c;
}

static int is_word(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '#' || c == '_';
}

/* Whole-word, ASCII case-insensitive search. text_len <= AS_MAX_TEXT_LEN and
 * sl <= AS_MAX_SKILL_LEN are guaranteed by the caller, so i + sl cannot wrap. */
static uint8_t contains_word(const uint8_t *text, size_t tl,
                             const uint8_t *s, size_t sl) {
    size_t i, j;
    if (sl == 0u || sl > tl) {
        return 0u;
    }
    for (i = 0u; i + sl <= tl; i++) {
        if (i > 0u && is_word(text[i - 1u])) {
            continue;
        }
        j = 0u;
        while (j < sl && fold(text[i + j]) == fold(s[j])) {
            j++;
        }
        if (j == sl && (i + sl == tl || !is_word(text[i + sl]))) {
            return 1u;
        }
    }
    return 0u;
}

int32_t as_skill_hits(const uint8_t *text, size_t text_len,
                      const uint8_t *skills, size_t skills_len,
                      uint8_t *hit_mask, size_t mask_cap) {
    size_t n = 0u;
    size_t start = 0u;
    size_t i;

    if (hit_mask == NULL || (text == NULL && text_len != 0u) ||
        (skills == NULL && skills_len != 0u)) {
        return AS_ERR_NULL;
    }
    if (text_len > AS_MAX_TEXT_LEN || skills_len > AS_MAX_SKILLS_LEN) {
        return AS_ERR_TOO_LARGE;
    }

    for (i = 0u; i <= skills_len; i++) {
        if (i == skills_len || skills[i] == (uint8_t)'\n') {
            size_t len = i - start;
            if (len > 0u) {
                if (len > AS_MAX_SKILL_LEN) {
                    return AS_ERR_SKILL_TOO_LONG;
                }
                if (n >= AS_MAX_SKILLS) {
                    return AS_ERR_TOO_MANY_SKILLS;
                }
                if (n >= mask_cap) {
                    return AS_ERR_MASK_TOO_SMALL;
                }
                hit_mask[n] = contains_word(text, text_len, skills + start, len);
                n++;
            }
            start = i + 1u;
        }
    }
    return (int32_t)n;
}
