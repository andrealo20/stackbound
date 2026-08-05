/* Case: the call target arrives as a function parameter.
 *
 * Nothing in the binary says which function the caller passed, so no analysis
 * of this call site alone can narrow it down.  The only sound answer is "any
 * function whose address is taken anywhere in the image", and this case exists
 * to measure what that costs: the bound is dominated by the fattest
 * address-taken function in the program, whether or not it can really be
 * reached here.
 */
#include "../common/sb_runtime.h"

volatile uint32_t pick = 0u;

typedef uint32_t (*work_fn)(uint32_t);

static uint32_t work_small(uint32_t x)
{
    volatile uint32_t buf[8]; /* 32 bytes */
    return sb_consume(buf, 8u) + x;
}

static uint32_t work_big(uint32_t x)
{
    volatile uint32_t buf[64]; /* 256 bytes */
    return sb_consume(buf, 64u) + x;
}

/* Address-taken, never passed to apply().  A type-based analysis cannot help
 * here either: it has the same signature as the functions that are. */
uint32_t work_never(uint32_t x)
{
    volatile uint32_t buf[256]; /* 1024 bytes */
    return sb_consume(buf, 256u) + x;
}

work_fn volatile never_ref = work_never;

static uint32_t apply(work_fn f, uint32_t x)
{
    volatile uint32_t scratch[4];
    uint32_t acc = sb_consume(scratch, 4u);
    return acc + f(x); /* indirect call through a parameter */
}

const char *app_name(void) { return "param_fp"; }

void app_run(void)
{
    /* Read never_ref without calling it.  The read is what keeps the pointer in
     * the image: with -Wl,--gc-sections an initialised global that nothing
     * refers to is dropped together with its section, and the evidence that
     * work_never's address was taken disappears from the binary. */
    if (never_ref == work_small) {
        sink += 1u;
    }

    work_fn f = (pick != 0u) ? work_big : work_small;
    sink = apply(f, 5u);
}
