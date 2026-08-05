/* Minimal bare-metal runtime for the stackbound benchmark firmware.
 *
 * No libc: the firmware is built with -nostdlib -nostartfiles so that the only
 * code in the ELF is code we wrote.  That keeps the call graph small enough to
 * check by hand, which is what makes the analyser's output falsifiable.
 */
#ifndef SB_RUNTIME_H
#define SB_RUNTIME_H

#include <stdint.h>

extern volatile uint32_t sink;

/* ---- semihosting ------------------------------------------------------- */
void sb_write(const char *s);
void sb_write_u32(uint32_t v);          /* decimal, no padding */
void sb_kv(const char *key, uint32_t v); /* prints "key=<v>\n" */
void sb_exit(void);

/* ---- stack painting ---------------------------------------------------- */
#define SB_PAINT 0xC0DEFACEu

/* Fill the unused part of the main stack with SB_PAINT.  Called first thing in
 * Reset_Handler, before any deep call has happened. */
void sb_paint_stack(void);

/* Highest number of bytes of the main stack ever occupied since painting,
 * measured by scanning upwards for the first word that is no longer SB_PAINT. */
uint32_t sb_stack_watermark(void);

/* ---- NVIC -------------------------------------------------------------- */
void sb_irq_set_priority(uint32_t irqn, uint8_t prio);
void sb_irq_enable(uint32_t irqn);
void sb_irq_pend(uint32_t irqn); /* set pending: takes the interrupt immediately
                                  * if its priority allows preemption */

/* ---- helpers that defeat dead-store elimination ------------------------ */
/* Defined in its own translation unit and never inlined, so a local buffer
 * passed to it cannot be optimised away.  Returns a value derived from the
 * buffer so the writes are observable. */
uint32_t sb_consume(volatile uint32_t *buf, uint32_t n);

/* ---- application hooks ------------------------------------------------- */
void app_run(void);              /* provided by each case */
const char *app_name(void);      /* provided by each case */

#endif /* SB_RUNTIME_H */
