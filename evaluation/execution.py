import os
import subprocess
import tempfile
import multiprocessing
from typing import Optional, Dict
import time
import threading
from ipdb import set_trace
import re


class TimeoutException(Exception):
    pass


def remove_main_function(code: str) -> str:
    pattern = re.compile(r'int\s+main\s*\([^)]*\)\s*\{')
    match = pattern.search(code)
    if not match:
        return code

    start = match.start()
    brace_count = 0
    i = match.end() - 1
    while i < len(code):
        if code[i] == '{':
            brace_count += 1
        elif code[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                return code[:start] + code[i+1:]
        i += 1
    return code

def unsafe_execute(problem, completion, timeout, result):
    completion = remove_main_function(completion)
    def target():
        with tempfile.TemporaryDirectory() as temp_dir:
            if "MBCPP" in problem["task_id"]:
                cpp_code = "#include <bits/stdc++.h>" + "\n" + problem['prompt'] + completion + "\n" + problem["test"]
            else:
                cpp_code = "#include <bits/stdc++.h>" + "\n" + problem['declaration'] + completion + "\n" + problem["test"]

            cpp_file_path = os.path.join(temp_dir, "temp.cpp")
            executable_path = os.path.join(temp_dir, "temp_program.exe")

            with open(cpp_file_path, 'w') as f:
                f.write(cpp_code)

            compile_command = ["g++", cpp_file_path, "-o", executable_path]
            compile_process = subprocess.Popen(compile_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = compile_process.communicate()

            if compile_process.returncode != 0:
                result.append(f"Compilation failed: {stderr.decode()}")
                return

            try:
                res = run_program_with_timeout(executable_path, timeout)
                result.append(res)
            except TimeoutException:
                result.append("timed out")
            except Exception as e:
                result.append(f"failed: {e}")

    thread = threading.Thread(target=target)
    thread.start()
    thread.join(timeout + 1)
    if thread.is_alive():
        result.append("timed out")

def check_correctness(problem: Dict, completion: str, timeout: float, completion_id: Optional[int] = None) -> Dict:
    manager = multiprocessing.Manager()
    result = manager.list()

    p = multiprocessing.Process(target=unsafe_execute, args=(problem, completion, timeout, result))
    p.start()
    p.join(timeout + 2)
    if p.is_alive():
        p.terminate()
        p.join()

    if not result:
        result.append("timed out")

    return dict(
        task_id=problem["task_id"],
        passed=result[0] == "passed",
        result=result[0],
        completion_id=completion_id,
    )


def run_program_with_timeout(executable_path: str, timeout: float) -> str:
    try:
        process = subprocess.Popen(executable_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            return "timed out"
        if process.returncode != 0:
            return f"Program failed: {stderr.decode()}"
        return "passed"
    finally:
        process.stdout.close()
        process.stderr.close()
        process.wait()


if __name__ == "__main__":
    problem = {
        "task_id": "CPP/0",
        "declaration": """
            #include<stdio.h>
            #include<vector>
            #include<math.h>
            using namespace std;
            #include<algorithm>
            #include<stdlib.h>
            bool has_close_elements(vector<float> numbers, float threshold){
        """,
        "test": """
            #include <cassert>
            int main() {
                vector<float> a = {1.0, 2.0, 3.9, 4.0, 5.0, 2.2};
                assert(has_close_elements(a, 0.3) == true);
                assert(has_close_elements(a, 0.05) == false);
                return 0;
            }
        """
    }

    completion = """
            sort(numbers.begin(), numbers.end());
            for (size_t i = 1; i < numbers.size(); i++) {
                if (numbers[i] - numbers[i - 1] < threshold) {
                    return true;
                }
            }
            return false;
        }
    """

    timeout = 5
    result = check_correctness(problem, completion, timeout)
    print(result)
