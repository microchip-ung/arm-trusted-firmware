import sys,os
import lan966x

from arm_ds.debugger_v1 import Debugger
from arm_ds.debugger_v1 import DebugException

debugger = Debugger()

# Ensure target is stopped
debugger.getCurrentExecutionContext().getExecutionService().stop()

addr = lan966x.abs_addr(debugger, 0)

# Set PC, Clear old breakpoints
debugger.getCurrentExecutionContext().getExecutionService().setExecutionAddress(addr)
debugger.removeAllBreakpoints()

build = lan966x.get_build_path()

# Load stage BL1
lan966x.load_stage(debugger, "bl1",
                   build + "/bl1/bl1.elf",
                   build + "/bl1.bin")
