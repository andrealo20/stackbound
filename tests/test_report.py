"""What the tool says when it does not know something.

Everything here is built from values rather than from an ELF, because the point
is the reporting and the build gate, not the decoding: a call that vanished from
the call graph, a recursion depth that could mean two things, two static
functions with the same name.  Each of those is a case where going quiet would
lower the number the user is asked to trust.
"""

from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs

from stackbound.analyze import FunctionBound, Options, Result, _stated_activations
from stackbound.cli import EXIT_INCOMPLETE, EXIT_OK, EXIT_OVERFLOW, EXIT_UNBOUNDED, check
from stackbound.report import render, to_dict
from stackbound.thumb import _literal_ranges

# ---- recursion depth ------------------------------------------------------


def test_a_single_member_states_the_component_depth():
    k, ambiguous = _stated_activations(["ping", "pong"], {"ping": 5})
    assert k == 5
    assert not ambiguous


def test_per_function_counts_are_flagged_not_guessed():
    """ping(4) is five activations of the component and three of ping.  A user
    who counted per function writes 3 and 2; reading that as 3 would cover three
    frames where five are on the stack, so the sum is used and the component is
    flagged."""
    k, ambiguous = _stated_activations(["ping", "pong"], {"ping": 3, "pong": 2})
    assert ambiguous
    assert k == 5


def test_repeating_the_total_on_every_member_is_ambiguous_too():
    """{"ping": 5, "pong": 5} could be the component total written twice, or
    five activations each.  It reads the same way, so it is flagged the same,
    and the pessimistic reading is the one taken."""
    k, ambiguous = _stated_activations(["ping", "pong"], {"ping": 5, "pong": 5})
    assert ambiguous
    assert k == 10


def test_a_self_recursive_function_is_never_ambiguous():
    k, ambiguous = _stated_activations(["descend"], {"descend": 7})
    assert (k, ambiguous) == (7, False)


def test_no_statement_leaves_the_component_unbounded():
    assert _stated_activations(["ping", "pong"], {}) == (None, False)


# ---- literal pool widths --------------------------------------------------


def _decode(code: bytes):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    return list(md.disasm(code, 0x1000))


def test_pool_width_comes_from_the_destination_register():
    """vldr into a D register takes eight bytes out of the pool, into an S
    register only four.  Claiming eight for the single-precision form would hide
    a real instruction sitting in the four bytes after the literal."""
    single = _literal_ranges(_decode(b"\x9f\xed\x02\x0a"))  # vldr s0, [pc, #8]
    double = _literal_ranges(_decode(b"\x9f\xed\x02\x0b"))  # vldr d0, [pc, #8]
    pair = _literal_ranges(_decode(b"\xdf\xe9\x02\x01"))  # ldrd r0, r1, [pc, #8]

    assert [end - start for start, end in single] == [4]
    assert [end - start for start, end in double] == [8]
    assert [end - start for start, end in pair] == [8]


# ---- the build gate -------------------------------------------------------


def _result(bounds, reachable, total=100, stack_region=(0x20000000, 0x20001000)):
    by_addr = {fb.addr: fb for fb in bounds}
    return Result(
        entry_name="Reset_Handler",
        thread_bound=total,
        exception_bound=0,
        total=total,
        handlers=[],
        level_costs={},
        bounds=by_addr,
        resolutions=[],
        tier_counts={},
        unbounded=sorted({fb.name for fb in bounds if fb.unbounded}),
        flagged={fb.name: fb.flags for fb in bounds if fb.flags},
        worst_path=["Reset_Handler"],
        stack_region=stack_region,
        options=Options(),
        reachable=set(reachable),
    )


def _fb(name, addr, **kw):
    return FunctionBound(name=name, addr=addr, local=0, bound=0, **kw)


def test_a_firmware_that_fits_passes():
    r = _result([_fb("main", 0x100)], reachable=[0x100])
    assert check(r, quiet=True) == EXIT_OK


def test_unreachable_recursion_does_not_fail_the_build():
    """Dead code cannot overflow anything.  It is still reported."""
    live = _fb("main", 0x100)
    dead = _fb("orphan", 0x200, unbounded=True, flags=["recursive"])
    r = _result([live, dead], reachable=[0x100])
    assert r.unbounded == ["orphan"]
    assert r.reachable_unbounded == []
    assert check(r, quiet=True) == EXIT_OK
    assert "no root reaches" in render(r)


def test_reachable_recursion_fails_the_build():
    r = _result(
        [_fb("main", 0x100), _fb("descend", 0x200, unbounded=True, flags=["recursive"])],
        reachable=[0x100, 0x200],
    )
    assert check(r, quiet=True) == EXIT_UNBOUNDED


def test_allow_unbounded_never_passes():
    """The total for a component with no stated depth is the cost of one
    activation, so exit 0 there would certify a firmware that overflows."""
    r = _result(
        [_fb("descend", 0x200, unbounded=True, flags=["recursive"])],
        reachable=[0x200],
    )
    assert check(r, allow_unbounded=True, quiet=True) == EXIT_INCOMPLETE


def test_allow_unbounded_still_reports_a_lower_bound_that_does_not_fit():
    r = _result(
        [_fb("descend", 0x200, unbounded=True, flags=["recursive"])],
        reachable=[0x200],
        total=99999,
    )
    assert check(r, allow_unbounded=True, quiet=True) == EXIT_OVERFLOW


def test_a_dropped_call_edge_fails_the_build():
    """A call to a symbol with no size leaves the call graph, and with it the
    callee's frame.  The bound goes down, so the check must refuse."""
    caller = _fb("main", 0x100, flags=["unknown_callee"], unknown_callees=[0x800])
    r = _result([caller], reachable=[0x100])
    assert r.reachable_unknown_callees == ["main"]
    assert check(r, quiet=True) == EXIT_UNBOUNDED
    assert "0x00000800" in render(r)
    assert to_dict(r)["unknown_callees"] == {"main": ["0x00000800"]}


def test_a_dropped_call_edge_in_dead_code_does_not_fail_the_build():
    caller = _fb("orphan", 0x300, flags=["unknown_callee"], unknown_callees=[0x800])
    r = _result([_fb("main", 0x100), caller], reachable=[0x100])
    assert check(r, quiet=True) == EXIT_OK
    assert to_dict(r)["unknown_callees"] == {"orphan": ["0x00000800"]}


def test_no_stack_size_is_not_an_overflow():
    """Nothing to compare against is a different answer from 'does not fit'."""
    r = _result([_fb("main", 0x100)], reachable=[0x100], stack_region=None)
    assert check(r, quiet=True) == EXIT_INCOMPLETE


def test_a_bound_larger_than_the_region_fails():
    r = _result([_fb("main", 0x100)], reachable=[0x100], total=99999)
    assert check(r, quiet=True) == EXIT_OVERFLOW


# ---- the machine-readable report ------------------------------------------


def test_two_static_functions_with_the_same_name_both_survive():
    """`static void helper(void)` in two translation units is two functions.
    Keying the JSON on the name alone would let one overwrite the other."""
    r = _result(
        [
            FunctionBound(name="helper", addr=0x100, local=8, bound=8),
            FunctionBound(name="helper", addr=0x200, local=64, bound=64),
            FunctionBound(name="main", addr=0x300, local=4, bound=72),
        ],
        reachable=[0x300],
    )
    functions = to_dict(r)["functions"]
    assert len(functions) == 3
    assert functions["helper@0x00000100"]["bound"] == 8
    assert functions["helper@0x00000200"]["bound"] == 64
    assert functions["main"]["bound"] == 72, "a unique name keeps its plain key"
