/* Case: call through a mutable global function pointer.
 *
 * The value is not known statically, so the candidate set has to come from the
 * type.  The pointer's DWARF type is uint32_t(*)(uint32_t); the two decoys have
 * different signatures and must be excluded, otherwise the bound is dominated
 * by a function that can never be called through this site.
 */
#include "../common/sb_runtime.h"

volatile uint32_t choose = 1u;

typedef uint32_t (*hook_fn)(uint32_t);

hook_fn volatile g_hook; /* mutable global, assigned and read at run time */

uint32_t hook_a(uint32_t x)
{
    volatile uint32_t buf[24]; /* 96 bytes */
    return sb_consume(buf, 24u) + x;
}

uint32_t hook_b(uint32_t x)
{
    volatile uint32_t buf[96]; /* 384 bytes */
    return sb_consume(buf, 96u) + x;
}

/* Decoy 1: same arity, different parameter type. */
uint32_t decoy_ptr(const char *s)
{
    volatile uint32_t buf[300]; /* 1200 bytes */
    sink = (uint32_t)s;
    return sb_consume(buf, 300u);
}

/* Decoy 2: different arity. */
uint32_t decoy_two(uint32_t a, uint32_t b)
{
    volatile uint32_t buf[500]; /* 2000 bytes */
    return sb_consume(buf, 500u) + a + b;
}

/* Force both decoys to be address-taken without ever calling them through
 * g_hook. */
uint32_t (*volatile decoy_ref_1)(const char *)       = decoy_ptr;
uint32_t (*volatile decoy_ref_2)(uint32_t, uint32_t) = decoy_two;

const char *app_name(void) { return "global_fp"; }

void app_run(void)
{
    g_hook = (choose != 0u) ? hook_b : hook_a;
    sink   = g_hook(3u);
}
