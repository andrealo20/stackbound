#include "sb_runtime.h"

/* Shared observable sink: every benchmark case writes to it so that its work
 * cannot be optimised away. */
volatile uint32_t sink;

/* ---- semihosting ------------------------------------------------------- */

#define SYS_WRITE0 0x04
#define SYS_EXIT   0x18

static void semihost(uint32_t op, uint32_t arg)
{
    register uint32_t r0 __asm__("r0") = op;
    register uint32_t r1 __asm__("r1") = arg;
    __asm__ volatile("bkpt 0xAB" : "+r"(r0) : "r"(r1) : "memory");
}

void sb_write(const char *s) { semihost(SYS_WRITE0, (uint32_t)s); }

void sb_exit(void) { semihost(SYS_EXIT, 0x20026u); }

void sb_write_u32(uint32_t v)
{
    char buf[12];
    int i = 11;
    buf[i--] = '\0';
    if (v == 0u) {
        buf[i--] = '0';
    } else {
        while (v != 0u && i >= 0) {
            buf[i--] = (char)('0' + (v % 10u));
            v /= 10u;
        }
    }
    sb_write(&buf[i + 1]);
}

void sb_kv(const char *key, uint32_t v)
{
    sb_write(key);
    sb_write("=");
    sb_write_u32(v);
    sb_write("\n");
}

/* ---- stack painting ---------------------------------------------------- */

extern uint32_t _stack_bottom;
extern uint32_t _stack_top;

/* Leave this many bytes below the current stack pointer unpainted, so that
 * painting cannot clobber its own frame or the return address. */
#define PAINT_MARGIN 64u

void sb_paint_stack(void)
{
    uint32_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));

    uint32_t *p     = &_stack_bottom;
    uint32_t *limit = (uint32_t *)((sp - PAINT_MARGIN) & ~3u);

    while (p < limit) {
        *p++ = SB_PAINT;
    }
}

uint32_t sb_stack_watermark(void)
{
    const uint32_t *p   = &_stack_bottom;
    const uint32_t *top = &_stack_top;

    while (p < top && *p == SB_PAINT) {
        p++;
    }
    return (uint32_t)((const uint8_t *)top - (const uint8_t *)p);
}

/* ---- NVIC -------------------------------------------------------------- */

#define NVIC_ISER0 ((volatile uint32_t *)0xE000E100u)
#define NVIC_ISPR0 ((volatile uint32_t *)0xE000E200u)
#define NVIC_IPR   ((volatile uint8_t *)0xE000E400u)

void sb_irq_set_priority(uint32_t irqn, uint8_t prio) { NVIC_IPR[irqn] = prio; }

void sb_irq_enable(uint32_t irqn)
{
    NVIC_ISER0[irqn >> 5] = 1u << (irqn & 31u);
    __asm__ volatile("dsb" ::: "memory");
    __asm__ volatile("isb" ::: "memory");
}

void sb_irq_pend(uint32_t irqn)
{
    NVIC_ISPR0[irqn >> 5] = 1u << (irqn & 31u);
    __asm__ volatile("dsb" ::: "memory");
    __asm__ volatile("isb" ::: "memory");
}
