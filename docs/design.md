# Design notes

## 1. The problem

A Cortex-M has no MMU and no guard page. When the stack grows past its region it
writes over whatever is next in RAM, usually `.bss`, and the failure appears
somewhere else entirely, minutes later, as corrupted state. Testing does not find
it reliably, because the deepest path is by construction the one that rarely
runs: the error branch inside the interrupt handler that fires while the parser
is at its deepest recursion.

So the question is not "how much stack did it use in my test" but "how much can
it possibly use". That is a static question, and it has three parts:

1. how much each function allocates, and how much is already held when it calls
   another one;
2. which functions an indirect call can reach;
3. what interrupts can be stacked on top of all that, and how deep.

Free tools answer (1). This project is about (2) and (3), and about checking the
answer against a real execution instead of asserting it.

## 2. Prior art, and where it stops

The survey done before writing any code. It is a survey, not a proof that
nothing else exists:

* **`cargo-call-stack`**: whole-program analysis for Rust on Cortex-M. Does not
  analyse indirect calls: the machine code carries no type information usable to
  build a callee list, so it warns and gives up. Cannot compute a whole-program
  maximum when exceptions are present, because handlers are disconnected nodes.
* **GCC `-fstack-usage` post-processors**: `avstack.pl`, `WorstCaseStack`,
  `checkStackUsage`, `puncover`. Per-function frames from the compiler, call
  graph from the source or the map file. Same two gaps, plus a dependency on
  `.su` files that only exist if the build produced them.
* **AbsInt StackAnalyzer**: handles recursion and function pointers, with
  qualification kits for DO-178B/C, ISO 26262, IEC 61508, EN 50128. Commercial.

The split is clean: open source covers direct calls with interrupts ignored,
commercial covers the rest. That gap is the whole reason this project is worth
writing, and it was worth ten minutes of searching to find out that it exists
before writing a line.

## 3. The bound

For a function $f$ with local allocation $L(f)$ and call sites $c$:

$$ S(f) = \max\Big( L(f), \max_{c \in \mathrm{calls}(f)} \big( d(c) + \max_{g \in T(c)} S(g) \big) \Big) $$

where $d(c)$ is the stack in use at the moment of the call and $T(c)$ the set of
possible callees.

Using $d(c)$ instead of $L(f)$ matters. A function that allocates a 512-byte
buffer *after* its calls have returned never holds the buffer and the callee at
the same time; charging $L(f)$ at every call site would add 512 bytes of
pessimism to every path through it. Recovering $d(c)$ requires knowing the value
of `SP` at each instruction, which is section 4.

### Recursion

A cycle has no finite bound. With a stated number of activations $k$ for a
strongly connected component:

$$ S(\mathrm{SCC}) = (k-1) \max_{\text{back edges}} d + \max_{f \in \mathrm{SCC}} S_{\mathrm{exit}}(f) $$

$k-1$ activations each reach their deepest recursion site, and the last one runs
to its own maximum. Without $k$ the component is reported unbounded and
`stackbound check` fails. Returning a number here would be the single most
dangerous thing the tool could do, because it would look exactly like a correct
answer.

$k$ counts activations of the component, not of any one function in it. For
mutual recursion this is the distinction that decides whether the bound holds:
`ping(4)` runs `ping, pong, ping, pong, ping`, which is five activations of the
component and three of `ping`. Stating 3 because `ping` is entered three times
would cover three frames where five are on the stack. The number is a property
of the component, so it is stated once, on any one of its members. When two
members carry numbers that add up to more than the largest of them, that is what
a per-function count looks like, and the component is flagged
`recursion_depth_ambiguous` rather than read either way in silence. The reading
used with the flag is their sum, which is exact if they were per-function counts
and pessimistic if the total was repeated. The maximum would be wrong in the
first case, and wrong downwards.

### Exceptions

$$ S_{\mathrm{exc}} = \sum_{\ell \in \mathrm{levels}} \max_{h \in \ell} \big( F + \mathrm{align} + S(h) \big) $$

$F$ is 32 bytes (r0-r3, r12, LR, PC, xPSR) or 104 with an FP context, and
`STKALIGN` can cost one padding word per entry. A chain contains at most one
handler per preemption level, because two handlers at the same level tail-chain
rather than nest; taking the most expensive at each level and summing gives the
worst chain the priority configuration admits.

Preemption level is `priority >> (PRIGROUP + 1)`: with PRIGROUP $= g$ the low
$g+1$ bits are subpriority, which orders tail-chaining but does not enable
nesting. A handler whose priority is not known statically gets a unique level,
which lets it nest with everything, the conservative choice.

The extended frame is counted in full even when lazy FP stacking is enabled: lazy
stacking reserves the space on exception entry and fills it later, so the stack
is occupied either way. The number of implemented priority bits is not modelled;
a device that ignores the low bits may merge two levels this tool keeps apart,
which makes the bound larger than necessary and never smaller.

The total is thread-mode depth plus the exception chain, because an interrupt can
arrive at the deepest point of thread mode.

## 4. Recovering SP

Per function: disassemble, build the intra-procedural CFG, run a forward fixpoint
carrying the stack depth at each instruction. Depth at a join point must agree
across predecessors; when it does not, the larger value is taken and the function
is flagged.

Instructions that move `SP`: `push`/`pop`, `vpush`/`vpop` (4 or 8 bytes per
register depending on whether the list is S or D registers), `stmdb`/`ldmia` with
`sp!`, `add`/`sub` with an immediate, and SP-based loads and stores with
writeback in either indexing form.

Anything else that writes `SP`, `mov sp, r7`, `sub sp, sp, r3` for a variable
length array, is not modelled. The function is flagged and falls back to a bound
that holds under any control flow: the sum of every allocation in it. Dynamic
allocation makes the function unbounded outright.

The point of the flag is that the failure is loud. A silent wrong number from a
stack analyser is worse than no analyser, because it will be believed.

### Hand-check

`firmware/build/direct.elf`, from `arm-none-eabi-objdump -d`:

```
level_a:  push {r4, lr}     8
          sub  sp, #128   +128  = 136 held at the call to level_b
level_b:  push {r4, lr}     8
          sub  sp, #256   +256  = 264 held at the call to level_c
level_c:  push {lr}         4
          sub  sp, #68     +68  =  72 held at the call to sb_consume
sb_consume: push {r4}       4
```

with `Reset_Handler` and `app_run` each holding 8 at their calls:

$$ 8 + 8 + 136 + 264 + 72 + 4 = 492 $$

The tool reports 492. The firmware, painting its own stack and reading the
watermark back after execution on a Cortex-M3 in QEMU, reports 492. Three
independent routes to the same number: arithmetic on the disassembly, the
analyser, and the hardware model.

## 5. How the numbers are checked

**Against an execution, not against itself.** Every firmware paints its stack
with `0xC0DEFACE` at reset, runs, and scans upward for the first word that is no
longer the pattern. That measurement comes out of QEMU's model of a Cortex-M3,
including the exception frames the hardware pushes, which no part of the analyser
is involved in producing. `tools/validate.py` compares the two for every case.

The watermark measures how far the stack was *written*, not how far `SP`
travelled. A function that does `sub sp, #256` and writes only the first half
leaves the rest of its frame painted, and the watermark stops there. So the
measured column is itself a lower bound on the real usage, and the two columns
coincide on this benchmark by construction: every case passes its buffer to
`sb_consume`, which touches every word of it. That is what makes the comparison
meaningful here, and it is also why "measured" must not be read as ground truth
on firmware that does not do the same.

Two consequences for the direction of the check. A bound below the watermark is
conclusively wrong, which is the property `validate.py` tests. A bound above it
proves nothing on its own, because the watermark can be short of the real
maximum for two independent reasons: the run may not have taken the deepest
path, and the deepest path may not have written everything it allocated.

**Against exhaustive enumeration.** The linear worst-chain formula is checked
against `worst_chain_bruteforce`, which enumerates every admissible nesting
order, on 40 randomised handler sets with random priorities, priority groupings
and FP settings. A formula that missed a chain, or allowed one the hardware
forbids, disagrees.

**Against deliberate sabotage.** `tools/sabotage.py` applies six mutations,
plausible mistakes, not typos, and records which test catches each:

| mutation | caught by |
|---|---|
| forget the hardware exception frame | `test_bound_is_never_below_the_measured_watermark[isr_nesting]` |
| assume interrupts cannot nest | `test_exception_bound_needs_the_configuration` |
| ignore the caller's depth at a call site | `test_bound_is_the_sum_along_the_worst_path` |
| read only the first entry of a const table | `test_const_table_is_read_exactly` |
| decode literal pools as instructions | `test_no_function_is_flagged_in_the_benchmark` |
| treat a recursive component as called once | `test_deeper_recursion_costs_more` |

6 of 6. A test that has never been seen to fail is not yet a test.

**Ablation.** Every case is analysed in four modes, so the claim "modelling
interrupts matters" is a measured difference and not an opinion:

| case | measured | full | interrupts ignored | indirect ignored | indirect unresolved |
|---|---:|---:|---:|---:|---:|
| `direct` | 492 | 492 | 492 | 492 | 492 |
| `table` | 556 | 556 | 556 | **48** | 1644 |
| `global_fp` | 412 | 412 | 412 | **48** | 2036 |
| `param_fp` | 92 | 1084 | 1084 | **52** | 1084 |
| `recursion` | 580 | 580 | 580 | 580 | 580 |
| `isr_nesting` | 684 | 708 | **276** | 708 | 708 |

Bold entries are bounds *below* the measured watermark: a tool reporting them
would certify a firmware that overflows.

## 6. What went wrong

**Literal pools decoded as code.** The first version disassembled each function
from its symbol start to its end and interpreted everything. GCC puts constant
pools inside function bounds, and a `.word` such as `0x20002008` disassembles
into a perfectly plausible instruction. Symptom: `incomplete_cfg` on a third of
the functions, including two-instruction leaves like `app_name`. Two separate
bugs behind one symptom, unreachable "instructions" tripping the CFG check, and
the risk of a fake `SP` write corrupting the depth. Fix: locate pools from the
`ldr rX, [pc, #imm]` instructions that reference them, then re-decode in segments
between them, repeating until the pool set stops changing.

**`ldr.w pc, [sp], #4` classified as an indirect branch.** GCC emits this as a
one-instruction return-and-pop. The decoder saw a load into PC and called it an
indirect jump, and the post-indexed writeback was an unmodelled `SP` write, so
every small leaf function was flagged. Fix: a load into PC with `SP` as base is a
return, and post-indexed writeback moves `SP` by the immediate operand.

**Alignment padding mistaken for lost control flow.** After the pool fix, four
functions were still flagged. The unreachable instruction was a single `nop`
between the last real instruction and the pool. Fix: unreachable `nop` padding
does not count as lost control flow.

**`Reset_Handler` as a candidate for every unresolved call.** Its address is in
the vector table, so it is address-taken, so the `any` tier included it, which
made the call graph one enormous cycle through the reset handler and every bound
unbounded. The measured symptom was `param_fp` reporting UNBOUNDED with a bound
of 1068. Fix: distinguish addresses taken by the vector table from addresses
taken by code. This is an assumption about firmware, not a theorem, so it is
documented in the README and can be switched off.

**`--gc-sections` deleted the evidence.** In `param_fp`, `work_never`'s address
is taken by an initialised global that nothing reads. Without `-fdata-sections`
the linker drops the whole input `.data` section as unreferenced, and the fact
that the address was ever taken vanishes from the image. The analyser was right
about the binary it was given. The case now reads the pointer without calling it,
which keeps the section alive, and the effect is in the limitations, because it
applies to real firmware too.

**A `sink` symbol defined per case.** Not interesting, but it is the reason the
first build of five ELFs produced one. Moved to the common runtime.

**The benchmark startup only works under QEMU.** `common/mps2.ld` places `.data`
in RAM with no load address in flash, and `Reset_Handler` clears `.bss` but
copies nothing. Both are wrong for a real board, where the initialisers live in
flash and have to be copied at reset; they work here only because QEMU loads
every `PT_LOAD` segment directly to its virtual address. Found while reviewing
the linker script, and left alone deliberately: every number in
`results/results.json` was measured with this startup path, and a different one
would move the measurements without any way to re-measure them. It is a comment
in the linker script instead.

## 7. What was deliberately not built

**WCET in cycles.** The original plan had instruction-level timing alongside
stack depth. It was cut before implementation for one reason: nothing available
here can check it. QEMU is not cycle-accurate, Renode is not either, and there is
no hardware. Every other number in this repository is validated against something
that did not come from the analyser; a timing number would have been the only one
that was not, and it would have been the one a reader had most reason to doubt.

**PSP and per-task stacks.** An RTOS splits thread mode across per-task stacks
with the handler chain landing on MSP, which turns one bound into one bound per
task plus a shared handler bound. That is a real and useful extension, and it is
the obvious next milestone; it is not in scope for a first version whose claim is
that its numbers are checked.

## 8. Reproducing

```sh
make -C firmware && python3 tools/validate.py && python3 tools/sabotage.py
```

Environment used for the numbers in this document: Ubuntu 24.04,
`arm-none-eabi-gcc` 13.2.1, `qemu-system-arm` 8.2.2, machine `mps2-an385`,
CPU `cortex-m3`, Python 3.12, `pyelftools` 0.33, `capstone` 5.0.
