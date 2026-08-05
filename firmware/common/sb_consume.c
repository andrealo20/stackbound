#include "sb_runtime.h"

/* Kept in its own translation unit and compiled without LTO so that GCC cannot
 * see through it.  Without this, every local buffer in the benchmark cases is
 * dead and gets optimised away, and the measured watermark collapses to the
 * cost of the call frames alone. */
uint32_t sb_consume(volatile uint32_t *buf, uint32_t n)
{
    uint32_t acc = 0u;
    for (uint32_t i = 0u; i < n; i++) {
        buf[i] = i * 2654435761u;
        acc += buf[i];
    }
    return acc;
}
