import ast
import signal
import astunparse
from .executor_utils import function_with_timeout
from typing import List
from .executor_types import ExecuteResult, Executor
from ipdb import set_trace
TEST_HEADER = "#undef NDEBUG\n#include<assert.h>\nint main(){\n"

class CppExecutor(Executor):
    def execute(self, func: str, tests: List[str], test: str, timeout: int = 1) -> ExecuteResult:
        main_start = test.find("int main(){")
        if main_start != -1:
            test_header = test[:main_start + len("int main(){")]
            func_test_list = [f'{func}\n{test_header}\n{test}\nreturn 0;\n}}' for test in tests]
        else:
            func_test_list = [f'{func}\nint main(){{\n{test}\nreturn 0;\n}}' for test in tests]
        print("|| Begin Executing...")
        success_tests = []
        failed_tests = []
        is_passing = True
        output = ""
        num_tests = len(func_test_list)
        for i in range(num_tests):
            try:
                output = function_with_timeout(exec, (func_test_list[i], globals()), timeout, language="cpp")
                if output.returncode != 0:
                    failed_tests += [f"{tests[i]} # Error: {output.stderr.decode()}"]
                    is_passing = False
                else:
                    success_tests += [tests[i]]
            except Exception as e:
                failed_tests += [f"{tests[i]} # Error: {str(e)}"]
                is_passing = False
        state = []
        print("|| End Executing...")
        return ExecuteResult(is_passing, failed_tests, state)

    def evaluate(self, name: str, func: str, test: str, timeout: int = 1) -> bool:
        code = f'{func}\n{test}\n'
        try:
            function_with_timeout(exec, (code, globals()), timeout, language="cpp")
            return True
        except Exception:
            return False