/* Case: bounded-in-practice recursion that is unbounded to a static analyser.
 *
 * The recursion depth comes from a volatile, so no static analysis can bound it
 * from the binary alone.  The correct behaviour is to report a cycle and refuse
 * to give a number, unless the user supplies the depth as an annotation.
 * A tool that silently returns a bound here is lying.
 */
#include "../common/sb_runtime.h"

volatile uint32_t depth = 6u;

static uint32_t descend(uint32_t n)
{
    volatile uint32_t buf[16]; /* 64 bytes per activation */
    uint32_t acc = sb_consume(buf, 16u);
    if (n == 0u) {
        return acc;
    }
    return acc + descend(n - 1u);
}

/* Mutual recursion, to exercise cycle detection on a strongly connected
 * component larger than one node. */
static uint32_t ping(uint32_t n);

static uint32_t pong(uint32_t n)
{
    volatile uint32_t buf[8];
    uint32_t acc = sb_consume(buf, 8u);
    return (n == 0u) ? acc : acc + ping(n - 1u);
}

static uint32_t ping(uint32_t n)
{
    volatile uint32_t buf[8];
    uint32_t acc = sb_consume(buf, 8u);
    return (n == 0u) ? acc : acc + pong(n - 1u);
}

const char *app_name(void) { return "recursion"; }

void app_run(void)
{
    sink = descend(depth);
    sink += ping(4u);
}
