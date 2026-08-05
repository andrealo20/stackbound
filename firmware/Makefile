CROSS   ?= arm-none-eabi-
CC       = $(CROSS)gcc
OBJCOPY  = $(CROSS)objcopy

CPU     ?= cortex-m3
BUILD   ?= build

# -O1 -fno-inline keeps the call graph in the binary.  With -O2 GCC inlines the
# whole benchmark into one function, which would make the call-graph analysis
# trivially correct and the benchmark meaningless.
CFLAGS  = -mcpu=$(CPU) -mthumb -O1 -fno-inline -fno-common \
          -g3 -gdwarf-4 -ffreestanding -nostdlib -nostartfiles \
          -Wall -Wextra -Wpedantic -Wconversion -Werror -std=c99
LDFLAGS = -T common/mps2.ld -Wl,-Map=$@.map -Wl,--gc-sections

COMMON  = common/startup.c common/sb_runtime.c common/sb_consume.c
CASES   = direct table global_fp param_fp recursion isr_nesting
ELVES   = $(addprefix $(BUILD)/,$(addsuffix .elf,$(CASES)))

all: $(ELVES)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.elf: cases/%.c $(COMMON) common/mps2.ld | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(COMMON) -o $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean
