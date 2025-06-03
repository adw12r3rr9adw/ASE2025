import angr
import claripy
from angr.exploration_techniques import LoopSeer
from hook import *
import subprocess
import os
import re
import logging
logging.getLogger('angr').setLevel(logging.ERROR)

def perform_symbolic_execution(project, func_addr, binary_file, max_steps, unroll):
    if isinstance(func_addr, str):
        func_addr = int(func_addr, 16)

    max_steps = 100
    call_state = project.factory.call_state(addr=func_addr)

    extra_options = {angr.options.SYMBOLIC_WRITE_ADDRESSES}
    initial_state = project.factory.entry_state(add_options=extra_options)

    
    call_state.regs.bp = call_state.regs.sp
    for reg in ['rdi', 'rsi', 'rdx', 'rcx']:
        setattr(call_state.regs, reg, claripy.BVS(f'{reg}', 64))
    simgr = project.factory.simgr(call_state)



    loop_seer = LoopSeer(bound=unroll)
    simgr.use_technique(loop_seer)

    simgr.run(n=max_steps)

    return simgr