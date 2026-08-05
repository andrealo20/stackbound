/* Case: plain direct calls.
 *
 * The deepest path is app_run -> level_a -> level_b -> level_c.  Every free
 * tool handles this case; it is here as the control experiment.
 */
#include "../common/sb_runtime.h"


static uint32_t level_c(void)
{
    volatile uint32_t buf[16]; /* 64 bytes */
    return sb_consume(buf, 16u);
}

static uint32_t level_b(void)
{
    volatile uint32_t buf[64]; /* 256 bytes */
    uint32_t acc = sb_consume(buf, 64u);
    return acc + level_c();
}

static uint32_t level_a(void)
{
    volatile uint32_t buf[32]; /* 128 bytes */
    uint32_t acc = sb_consume(buf, 32u);
    return acc + level_b();
}

/* A shallow sibling, so the analyser has to pick the deeper branch rather than
 * the last one it visited. */
static uint32_t shallow(void)
{
    volatile uint32_t buf[4];
    return sb_consume(buf, 4u);
}

const char *app_name(void) { return "direct"; }

void app_run(void)
{
    sink = shallow();
    sink += level_a();
}
