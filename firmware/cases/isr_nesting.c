/* Case: nested interrupts.
 *
 * Three external interrupts at three distinct preemption priorities.  Each
 * handler pends the next one up, so the hardware takes them immediately and the
 * stack ends up holding, at the same instant:
 *
 *   deep main path + [frame + IRQ0] + [frame + IRQ1] + [frame + IRQ2]
 *
 * This is the case where a tool that ignores exceptions reports a number that
 * is lower than what the hardware actually uses.
 */
#include "../common/sb_runtime.h"

#define IRQ_LOW  0u
#define IRQ_MID  1u
#define IRQ_HIGH 2u

void IRQ2_Handler(void)
{
    volatile uint32_t buf[16]; /* 64 bytes */
    sink += sb_consume(buf, 16u);
}

void IRQ1_Handler(void)
{
    volatile uint32_t buf[24]; /* 96 bytes */
    sink += sb_consume(buf, 24u);
    sb_irq_pend(IRQ_HIGH); /* preempted here */
    sink += buf[0];
}

void IRQ0_Handler(void)
{
    volatile uint32_t buf[32]; /* 128 bytes */
    sink += sb_consume(buf, 32u);
    sb_irq_pend(IRQ_MID); /* preempted here */
    sink += buf[0];
}

static uint32_t main_inner(void)
{
    volatile uint32_t buf[40]; /* 160 bytes */
    uint32_t acc = sb_consume(buf, 40u);
    sb_irq_pend(IRQ_LOW); /* the whole chain runs on top of this frame */
    return acc + buf[0];
}

static uint32_t main_outer(void)
{
    volatile uint32_t buf[20]; /* 80 bytes */
    uint32_t acc = sb_consume(buf, 20u);
    return acc + main_inner();
}

const char *app_name(void) { return "isr_nesting"; }

void app_run(void)
{
    sb_irq_set_priority(IRQ_LOW, 0xC0u);
    sb_irq_set_priority(IRQ_MID, 0x80u);
    sb_irq_set_priority(IRQ_HIGH, 0x40u);
    sb_irq_enable(IRQ_LOW);
    sb_irq_enable(IRQ_MID);
    sb_irq_enable(IRQ_HIGH);

    sink = main_outer();
}
