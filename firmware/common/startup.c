#include "sb_runtime.h"

extern uint32_t _stack_top;
extern uint32_t __bss_start;
extern uint32_t __bss_end;

void Reset_Handler(void);
void Default_Handler(void);

/* Weak IRQ handlers.  A case that wants an interrupt simply defines
 * IRQ0_Handler .. IRQ3_Handler and the strong symbol wins at link time. */
void IRQ0_Handler(void) __attribute__((weak, alias("Default_Handler")));
void IRQ1_Handler(void) __attribute__((weak, alias("Default_Handler")));
void IRQ2_Handler(void) __attribute__((weak, alias("Default_Handler")));
void IRQ3_Handler(void) __attribute__((weak, alias("Default_Handler")));

/* The first vector entry is the initial stack pointer, not a function.  ISO C
 * has no conforming way to write that, so the conversion is localised here. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
__attribute__((section(".vectors"), used))
void (*const vector_table[])(void) = {
    (void (*)(void)) & _stack_top, /*  0: initial MSP                     */
    Reset_Handler,                 /*  1: Reset                           */
    Default_Handler,               /*  2: NMI                             */
    Default_Handler,               /*  3: HardFault                       */
    Default_Handler,               /*  4: MemManage                       */
    Default_Handler,               /*  5: BusFault                        */
    Default_Handler,               /*  6: UsageFault                      */
    0, 0, 0, 0,                    /*  7-10: reserved                     */
    Default_Handler,               /* 11: SVCall                          */
    Default_Handler,               /* 12: DebugMonitor                    */
    0,                             /* 13: reserved                        */
    Default_Handler,               /* 14: PendSV                          */
    Default_Handler,               /* 15: SysTick                         */
    IRQ0_Handler,                  /* 16: external IRQ 0                  */
    IRQ1_Handler,                  /* 17: external IRQ 1                  */
    IRQ2_Handler,                  /* 18: external IRQ 2                  */
    IRQ3_Handler,                  /* 19: external IRQ 3                  */
};
#pragma GCC diagnostic pop

void Default_Handler(void)
{
    for (;;) {
    }
}

void Reset_Handler(void)
{
    for (uint32_t *p = &__bss_start; p < &__bss_end; p++) {
        *p = 0u;
    }

    sb_paint_stack();

    sb_write("case=");
    sb_write(app_name());
    sb_write("\n");

    app_run();

    /* Capture before printing: printing itself uses stack. */
    uint32_t used = sb_stack_watermark();
    sb_kv("measured_stack_bytes", used);
    sb_write("done\n");
    sb_exit();

    for (;;) {
    }
}
