import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIRMWARE = os.path.join(ROOT, "firmware")
BUILD = os.path.join(FIRMWARE, "build")

CASES = ["direct", "table", "global_fp", "param_fp", "recursion", "isr_nesting"]

have_gcc = shutil.which("arm-none-eabi-gcc") is not None
have_qemu = shutil.which("qemu-system-arm") is not None

needs_gcc = pytest.mark.skipif(not have_gcc, reason="arm-none-eabi-gcc not installed")
needs_qemu = pytest.mark.skipif(not have_qemu, reason="qemu-system-arm not installed")


@pytest.fixture(scope="session")
def firmware():
    """Build every benchmark case once per test session."""
    if not have_gcc:
        pytest.skip("arm-none-eabi-gcc not installed")
    subprocess.run(["make", "-s"], cwd=FIRMWARE, check=True)
    return {c: os.path.join(BUILD, f"{c}.elf") for c in CASES}


@pytest.fixture(scope="session")
def configs():
    return {c: os.path.join(FIRMWARE, "config", f"{c}.json") for c in CASES}
