/* Linker script for the QEMU mps2-an385 (Cortex-M3) and mps2-an386 (Cortex-M4F).
 *
 * The stack is given its own output section so that _stack_bottom and _stack_top
 * are real symbols in the ELF.  stackbound reads them to size the stack region,
 * and the firmware uses them to paint the stack and to measure the watermark.
 */

MEMORY
{
  CODE (rx)  : ORIGIN = 0x00000000, LENGTH = 4M
  RAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 4M
}

ENTRY(Reset_Handler)

STACK_SIZE = DEFINED(STACK_SIZE) ? STACK_SIZE : 8K;

SECTIONS
{
  .vectors : { KEEP(*(.vectors)) } > CODE

  .text :
  {
    *(.text*)
    *(.rodata*)
    . = ALIGN(4);
  } > CODE

  .data : { *(.data*) . = ALIGN(4); } > RAM
  .bss  : { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(4); __bss_end = .; } > RAM

  .stack (NOLOAD) :
  {
    . = ALIGN(8);
    _stack_bottom = .;
    . = . + STACK_SIZE;
    . = ALIGN(8);
    _stack_top = .;
  } > RAM

  /DISCARD/ : { *(.ARM.exidx*) *(.comment) }
}
