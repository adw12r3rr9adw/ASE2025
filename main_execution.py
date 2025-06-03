import argparse
import threading
import os
import re
import json
import logging
import shutil
import angr
from compiler import compile_cpp_code
from executor import perform_symbolic_execution
from analyzer import analyze_simgr
from utils import parse_map_file, get_function_address, print_paths_info
from ipdb import set_trace

logging.getLogger('angr').setLevel(logging.ERROR)

SYMBOLIC_EXECUTION_TIMEOUT = 120

def run_symbolic_execution_with_timeout(project, func_addr, binary_file, mode="experiment", max_steps=100, unroll=3):
    result = None
    stop_event = threading.Event()

    def worker():
        nonlocal result
        try:
            result = perform_symbolic_execution(project, func_addr, binary_file, max_steps, unroll)
        except Exception as e:
            print(f"Error during symbolic execution: {e}")
        finally:
            stop_event.set()

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=SYMBOLIC_EXECUTION_TIMEOUT)

    if not stop_event.is_set():
        print(f"Symbolic execution timeout (exceeded {SYMBOLIC_EXECUTION_TIMEOUT} seconds), forcefully terminating task.\n")
        if mode == "debug":
            print("Debug mode: exiting program directly.")
            os._exit(1)
        return None

    return result

def process_task(task_id, code, entry_point, output_dir, mode, counter=None, max_steps=100, unroll=3):
    if mode == "experiment" and counter is not None:
        unique_id = f"{task_id}_{counter}"
    else:
        unique_id = task_id

    safe_task_id = re.sub(r'[<>:"/\\|?*]', '_', task_id)
    safe_unique_id = re.sub(r'[<>:"/\\|?*]', '_', unique_id)

    task_output_dir = os.path.join(output_dir, safe_task_id)
    os.makedirs(task_output_dir, exist_ok=True)

    res_dir = os.path.join(task_output_dir, 'res')
    tmp_dir = os.path.join(task_output_dir, 'tmp')
    os.makedirs(res_dir, exist_ok=True)
    os.makedirs(tmp_dir, exist_ok=True)

    cpp_source_file = os.path.join(tmp_dir, f"{safe_unique_id}.cpp")
    code_with_main = code if "main()" in code else code + "\n\nint main() {}"
    with open(cpp_source_file, 'w', encoding='utf-8') as cpp_file:
        cpp_file.write(code_with_main)

    cpp_output_file = os.path.join(res_dir, f"{safe_unique_id}.cpp")
    shutil.copyfile(cpp_source_file, cpp_output_file)

    binary_file = os.path.join(tmp_dir, f"{safe_unique_id}_bin.exe")
    map_file = os.path.join(tmp_dir, f"{safe_unique_id}.map")
    output_file = os.path.join(res_dir, f"{safe_unique_id}.txt")

    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        print(f"Compiling task {safe_unique_id}...")
        try:
            success = compile_cpp_code(cpp_source_file, binary_file, map_file)
            if not success:
                print(f"Compilation failed, skipping task {safe_unique_id}.\n")
                return

            func_addr_dict = parse_map_file(map_file)
            project = angr.Project(binary_file, auto_load_libs=False)

            func_addr = get_function_address(func_addr_dict, entry_point)
            if func_addr is None:
                print(f"Function {entry_point} not found in task {task_id}.\n")
                return
            
            simgr = run_symbolic_execution_with_timeout(project, func_addr, binary_file, mode, max_steps, unroll)
            if simgr is None:
                return

            paths_info = analyze_simgr(simgr)
            pkl_file = os.path.join(res_dir, f"{safe_unique_id}.pkl")
            print_paths_info(paths_info, output_file, pkl_file)

        except Exception as e:
            print(f"Error occurred while processing task {safe_unique_id}: {e}\n")
            return

        print(f"Task {safe_unique_id} completed.\n")
    else:
        print(f"Task {safe_unique_id} already processed, skipping.\n")

def find_mixed_passed_tasks(jsonl_file_path):
    task_results = {}

    try:
        with open(jsonl_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                data = json.loads(line)
                task_id = data.get('task_id')
                passed = data.get('passed')

                if task_id is not None and passed is not None:
                    if task_id not in task_results:
                        task_results[task_id] = set()
                    task_results[task_id].add(passed)
    except FileNotFoundError:
        print(f"Error: File '{jsonl_file_path}' not found.")
        return set()
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSONL file: {e}")
        return set()

    mixed_passed_tasks = set()
    for task_id, passed_values in task_results.items():
        if True in passed_values and False in passed_values:
            mixed_passed_tasks.add(task_id)

    return mixed_passed_tasks

def main():
    parser = argparse.ArgumentParser(description="Symbolic Execution Tool")
    parser.add_argument("--mode", type=str, choices=["experiment", "debug"], default="debug")
    parser.add_argument("--model", type=str, default="4o")
    parser.add_argument("--dataset", type=str, default="MBPP")
    parser.add_argument("--begin", type=int)
    parser.add_argument("--end", type=int)
    parser.add_argument("--max_step", type=int, default=100)
    parser.add_argument("--unroll", type=int, default=3)
    args = parser.parse_args()

    mode = args.mode
    model = args.model
    dataset = args.dataset.lower()
    begin, end = args.begin, args.end
    max_steps, unroll = args.max_step, args.unroll

    output_dir = os.path.join('output', dataset, model)
    os.makedirs(output_dir, exist_ok=True)

    if mode == "experiment":
        merged_file = os.path.join('data', dataset, model, f"merged_{model}.jsonl")
        code_result_file = os.path.join('data', dataset, model, f"samples_{model}.jsonl_results.jsonl")
        task_counters = {}

        with open(merged_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines):
            data = json.loads(line)
            code = data['code']
            task_id = data['task_id']
            entry_point = data['entry_point']

            if begin is not None and end is not None:
                task_num = int(task_id.split('/')[-1])
                if task_num < begin or task_num >= end:
                    continue

            task_counters[task_id] = task_counters.get(task_id, 0) + 1
            counter = task_counters[task_id]

            process_task(task_id, code, entry_point, output_dir, mode, counter, max_steps, unroll)

    elif mode == "debug":
        cpp_source_file = 'example.cpp'
        task_id = 'example'

        with open(cpp_source_file, 'r', encoding='utf-8') as cpp_file:
            code = cpp_file.read()

        print(f"Processing debug task {task_id}...")
        entry_point = "add" 
        process_task(task_id, code, entry_point, output_dir, mode, max_steps, unroll)

    else:
        print("Invalid mode! Please use 'experiment' or 'debug'.")

if __name__ == '__main__':
    main()
