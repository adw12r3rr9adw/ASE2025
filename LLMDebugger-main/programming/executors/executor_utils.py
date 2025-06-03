
def timeout_handler(_, __):
    raise TimeoutError()

import os, json
from ipdb import set_trace
import tempfile
import subprocess
def to_jsonl(dict_data, file_path):
    with open(file_path, 'a') as file:
        json_line = json.dumps(dict_data)
        file.write(json_line + os.linesep)

from threading import Thread
class PropagatingThread(Thread):
    def run(self):
        self.exc = None
        try:
            if hasattr(self, '_Thread__target'):
                # Thread uses name mangling prior to Python 3.
                self.ret = self._Thread__target(*self._Thread__args, **self._Thread__kwargs)
            else:
                self.ret = self._target(*self._args, **self._kwargs)
        except Exception as e:
            self.exc = e

    def join(self, timeout=None):
        super(PropagatingThread, self).join(timeout)
        if self.exc:
            raise self.exc
        if self.is_alive():
            return None
        return self.ret
    
    def terminate(self):
        self._stop()
    

def function_with_timeout(func, args, timeout, language):
    result_container = []

    def wrapper():
        result_container.append(func(*args))

    if language == "python":
        thread = PropagatingThread(target=wrapper)
        thread.start()
        thread.join(timeout)

        if thread.is_alive():
            thread.terminate()
            raise TimeoutError()
        else:
            return result_container[0]
    elif language == "cpp":
        cpp_code = args[0]
        with tempfile.TemporaryDirectory() as temp_dir:
            cpp_file = os.path.join(temp_dir, "test.cpp")
            exe_file = os.path.join(temp_dir, "test")

            with open(cpp_file, "w") as f:
                f.write(cpp_code)

            compile_result = subprocess.run(
                ["g++", cpp_file, "-o", exe_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            
            if compile_result.returncode != 0:
                raise RuntimeError(f"Compilation failed: {compile_result.stderr.decode()}")

            try:
                run_result = subprocess.run(
                    [exe_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                )
                return run_result
            except subprocess.TimeoutExpired:
                raise TimeoutError("Execution timed out")
            except Exception as e:
                raise RuntimeError(f"Execution failed: {str(e)}")
        


