/*
 * Standalone C tests. CI builds this with AddressSanitizer + UBSan:
 *   cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
 *      -fno-sanitizer-recover=all c/matcher.c c/test_matcher.c -o test_matcher
 */
#include "matcher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static int32_t run(const char *text, const char *skills, uint8_t *mask,
                   size_t cap) {
    return as_skill_hits((const uint8_t *)text, strlen(text),
                         (const uint8_t *)skills, strlen(skills), mask, cap);
}

int main(void) {
    uint8_t mask[AS_MAX_SKILLS];
    uint8_t big[AS_MAX_TEXT_LEN + 1u];
    uint8_t bigskills[AS_MAX_SKILLS_LEN + 1u];
    size_t i;

    /* basic whole-word, case-insensitive */
    CHECK(run("We use Rust and SQL daily", "rust\nsql\ngo", mask, 8) == 3);
    CHECK(mask[0] == 1 && mask[1] == 1 && mask[2] == 0);

    /* java must not match inside javascript; c must not match inside c++ */
    CHECK(run("javascript developer", "java", mask, 8) == 1 && mask[0] == 0);
    CHECK(run("c++ developer", "c", mask, 8) == 1 && mask[0] == 0);
    CHECK(run("c++ developer", "c++", mask, 8) == 1 && mask[0] == 1);
    CHECK(run("knowledge of C/C++ preferred", "c", mask, 8) == 1 && mask[0] == 1);
    CHECK(run("C# and .NET", "c#", mask, 8) == 1 && mask[0] == 1);

    /* punctuation boundaries, start and end of text */
    CHECK(run("rust", "rust", mask, 8) == 1 && mask[0] == 1);
    CHECK(run("(rust),", "rust", mask, 8) == 1 && mask[0] == 1);
    CHECK(run("trust", "rust", mask, 8) == 1 && mask[0] == 0);
    CHECK(run("rusty", "rust", mask, 8) == 1 && mask[0] == 0);

    /* empty entries skipped; empty text */
    CHECK(run("abc", "\n\nabc\n\n", mask, 8) == 1);
    CHECK(run("", "rust", mask, 8) == 1 && mask[0] == 0);
    CHECK(run("text", "", mask, 8) == 0);

    /* skill longer than text */
    CHECK(run("ab", "abcdef", mask, 8) == 1 && mask[0] == 0);

    /* error paths */
    CHECK(as_skill_hits(NULL, 3, (const uint8_t *)"a", 1, mask, 8) == AS_ERR_NULL);
    CHECK(as_skill_hits((const uint8_t *)"a", 1, NULL, 3, mask, 8) == AS_ERR_NULL);
    CHECK(as_skill_hits((const uint8_t *)"a", 1, (const uint8_t *)"a", 1, NULL, 8) == AS_ERR_NULL);
    CHECK(run("a", "a\nb\nc", mask, 2) == AS_ERR_MASK_TOO_SMALL);

    memset(big, 'a', sizeof big);
    CHECK(as_skill_hits(big, AS_MAX_TEXT_LEN + 1u, (const uint8_t *)"a", 1, mask, 8) == AS_ERR_TOO_LARGE);
    CHECK(as_skill_hits(big, AS_MAX_TEXT_LEN, (const uint8_t *)"a", 1, mask, 8) == 1);

    memset(bigskills, 'a', sizeof bigskills);
    CHECK(as_skill_hits(big, 4, bigskills, AS_MAX_SKILLS_LEN + 1u, mask, 8) == AS_ERR_TOO_LARGE);
    CHECK(as_skill_hits(big, 4, bigskills, AS_MAX_SKILL_LEN + 1u, mask, 8) == AS_ERR_SKILL_TOO_LONG);
    CHECK(as_skill_hits(big, 4, bigskills, AS_MAX_SKILL_LEN, mask, 8) == 1);

    /* exactly the maximum number of skills, then one more */
    {
        uint8_t many[AS_MAX_SKILLS * 2u + 2u];
        size_t len = 0u;
        for (i = 0u; i < AS_MAX_SKILLS + 1u; i++) {
            many[len++] = 'x';
            many[len++] = '\n';
        }
        CHECK(as_skill_hits(big, 4, many, len - 2u, mask, AS_MAX_SKILLS) == (int32_t)AS_MAX_SKILLS);
        CHECK(as_skill_hits(big, 4, many, len, mask, AS_MAX_SKILLS + 1u) == AS_ERR_TOO_MANY_SKILLS);
    }

    /* non-ASCII bytes are treated as boundaries and compared bytewise */
    CHECK(run("caf\xc3\xa9 rust \xc3\xa9", "rust", mask, 8) == 1 && mask[0] == 1);

    if (failures == 0) {
        printf("c tests: ok\n");
        return 0;
    }
    fprintf(stderr, "c tests: %d failure(s)\n", failures);
    return 1;
}
