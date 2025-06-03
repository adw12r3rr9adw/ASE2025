import claripy

def analyze_simgr(simgr):
    paths_info = []
    for state in simgr.deadended:
        path_info = {
            'ret_expr': state.regs.eax if state.project.arch.bits == 32 else state.regs.rax,
            'constraints': state.solver.constraints,
            'addr': state.addr,
        }
        paths_info.append(path_info)
    for state in simgr.active:
        path_info = {
            'ret_expr': "",
            'constraints': state.solver.constraints,
            'addr': state.addr
        }
        paths_info.append(path_info)
    return paths_info