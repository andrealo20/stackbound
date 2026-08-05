/* Case: dispatch through a const table of function pointers.
 *
 * This is the dominant indirect-call pattern in embedded C (driver vtables,
 * state machines, command tables).  The table lives in a read-only section, so
 * its contents are known at link time and the candidate set is exact, not an
 * over-approximation.
 *
 * The index comes from a volatile, so the compiler cannot fold the call into a
 * direct one.
 */
#include "../common/sb_runtime.h"

volatile uint32_t selector = 2u;

typedef uint32_t (*cmd_fn)(uint32_t);

static uint32_t cmd_small(uint32_t x)
{
    volatile uint32_t buf[8]; /* 32 bytes */
    return sb_consume(buf, 8u) + x;
}

static uint32_t cmd_medium(uint32_t x)
{
    volatile uint32_t buf[48]; /* 192 bytes */
    return sb_consume(buf, 48u) + x;
}

static uint32_t cmd_large(uint32_t x)
{
    volatile uint32_t buf[128]; /* 512 bytes */
    return sb_consume(buf, 128u) + x;
}

/* Never placed in the table.  A sound-but-blind analyser that assumes "any
 * address-taken function" would have to include it, because its address is
 * taken below; reading the table excludes it. */
uint32_t cmd_orphan(uint32_t x)
{
    volatile uint32_t buf[400]; /* 1600 bytes */
    return sb_consume(buf, 400u) + x;
}

static cmd_fn const dispatch[4] = {cmd_small, cmd_medium, cmd_large, cmd_small};

volatile cmd_fn orphan_ref = cmd_orphan; /* takes the address, never called */

const char *app_name(void) { return "table"; }

void app_run(void)
{
    uint32_t acc = 0u;
    for (uint32_t i = 0u; i < 4u; i++) {
        if (i == selector) {
            acc += dispatch[i](i);
        }
    }
    acc += dispatch[selector](7u);
    sink = acc;
}
