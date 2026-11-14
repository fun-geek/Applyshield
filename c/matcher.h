/*
 * ApplyShield deterministic matching engine.
 *
 * Design rules (see docs/security-model.md, threat T6):
 *  - No heap allocation, no global state, no I/O. Pure function of its inputs.
 *  - Every input length is explicit; nothing relies on NUL termination.
 *  - Hard size limits are enforced before any scanning. Violations return a
 *    negative error code and never read or write out of bounds.
 *  - The caller owns all buffers, including the output mask.
 */
#ifndef APPLYSHIELD_MATCHER_H
#define APPLYSHIELD_MATCHER_H

#include <stddef.h>
#include <stdint.h>

#define AS_MAX_TEXT_LEN 65536u   /* bytes of job text scanned            */
#define AS_MAX_SKILLS_LEN 8192u  /* bytes of newline-separated skills    */
#define AS_MAX_SKILLS 128u       /* skills per call                      */
#define AS_MAX_SKILL_LEN 32u     /* bytes per skill                      */

#define AS_ERR_NULL (-1)
#define AS_ERR_TOO_LARGE (-2)
#define AS_ERR_TOO_MANY_SKILLS (-3)
#define AS_ERR_SKILL_TOO_LONG (-4)
#define AS_ERR_MASK_TOO_SMALL (-5)

/*
 * For each skill in `skills` (UTF-8/ASCII bytes separated by '\n'; empty
 * entries are skipped), write 1 to hit_mask[i] if the skill occurs in `text`
 * as a whole word, else 0. Matching is ASCII case-insensitive. A "word
 * character" is [A-Za-z0-9] plus '+', '#' and '_', so "c" does not match
 * inside "c++" and "java" does not match inside "javascript".
 *
 * Returns the number of skills processed (>= 0), or a negative AS_ERR_* code.
 * On error the contents of hit_mask are unspecified.
 */
int32_t as_skill_hits(const uint8_t *text, size_t text_len,
                      const uint8_t *skills, size_t skills_len,
                      uint8_t *hit_mask, size_t mask_cap);

#endif /* APPLYSHIELD_MATCHER_H */
