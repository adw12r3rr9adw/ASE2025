from roles import Analyst, Coder, Tester
from utils import find_method_name
import time
from utils import code_truncate
from ipdb import set_trace
import subprocess
import tempfile
import os
import shutil


class Session(object):
    def __init__(self, TEAM, ANALYST, CPP_DEVELOPER, TESTER, requirement, model='gpt-3.5-turbo-0301', majority=1, max_tokens=512,
                                temperature=0.0, top_p=1.0, max_round=4, before_func='', init_code=''):

        self.session_history = {}
        self.max_round = max_round
        self.before_func = before_func
        self.requirement = requirement
        self.init_code = init_code
        self.analyst = Analyst(TEAM, ANALYST, requirement, model, majority, max_tokens, temperature, top_p)
        self.coder = Coder(TEAM, CPP_DEVELOPER, requirement, model, majority, max_tokens, temperature, top_p)
        self.tester = Tester(TEAM, TESTER, requirement, model, majority, max_tokens, temperature, top_p)
    
    def run_session(self):
        plan = self.analyst.analyze()
        report = plan
        is_init=True
        self.session_history["plan"] = plan
        code = ""
        for i in range(self.max_round):
            if i!=0:
                code = self.coder.implement(report, is_init)
            else:
                code = self.init_code
            
            if code.strip() == "":
                if i == 0:
                    code = "error"
                else:
                    code = self.session_history['Round_{}'.format(i-1)]["code"]
                break
            
            if i == self.max_round-1:
                self.session_history['Round_{}'.format(i)] = {"code": code}
                break  
            tests = self.tester.test(code)
            test_report = code_truncate(tests)
            answer_report = unsafe_execute_cpp(code,test_report)
            report = f'The compilation output of the preceding code is: {answer_report}'

            is_init = False
            self.session_history['Round_{}'.format(i)] = {"code": code, "report": report}

            if (plan == "error") or (code == "error") or (report == "error"):
                code = "error"
                break
            
            if answer_report == "Code Test Passed.":
                break

        self.analyst.itf.clear_history()
        self.coder.itf.clear_history()
        self.tester.itf.clear_history()

        return code, self.session_history

    def run_analyst_coder(self):
        plan = self.analyst.analyze()
        is_init=True
        self.session_history["plan"] = plan
        code = self.coder.implement(plan, is_init)

        if (plan == "error") or (code == "error"):
            code = "error"

        self.analyst.itf.clear_history()
        self.coder.itf.clear_history()
        self.tester.itf.clear_history()

        return code, self.session_history


    def run_coder_tester(self):
        report = ""
        is_init=True
        code = ""
        
        for i in range(self.max_round):

            naivecode = self.coder.implement(report, is_init)
            if find_method_name(naivecode):
                code = naivecode

            if code.strip() == "":
                if i == 0:
                    code = self.coder.implement(report, is_init=True)
                else:
                    code = self.session_history['Round_{}'.format(i-1)]["code"]
                break
            
            if i == self.max_round-1:
                self.session_history['Round_{}'.format(i)] = {"code": code}
                break
            tests = self.tester.test(code)
            test_report = code_truncate(tests)
            answer_report = unsafe_execute(self.before_func+code+'\n'+test_report+'\n'+f'check({method_name})', '')
            report = f'The compilation output of the preceding code is: {answer_report}'

            is_init = False
            self.session_history['Round_{}'.format(i)] = {"code": code, "report": report}

            if (code == "error") or (report == "error"):
                code = "error"
                break
            
            if report == "Code Test Passed.":
                break

        self.analyst.itf.clear_history()
        self.coder.itf.clear_history()
        self.tester.itf.clear_history()

        return code, self.session_history

    def run_coder_only(self):
        plan = ""
        code = self.coder.implement(plan, is_init=True)
        self.coder.itf.clear_history()
        return code, self.session_history


import contextlib
import faulthandler
import io
import os
import platform
import signal
import tempfile 

def unsafe_execute_cpp(code: str, test_report: str) -> str:
    """
    Runs the given C++ code along with a test report in a safe, isolated environment and returns the result.
    """
    with tempfile.TemporaryDirectory() as tempdir:
        cpp_file = os.path.join(tempdir, "program.cpp")
        exe_file = os.path.join(tempdir, "program")
        
        # Combine code and test_report into a single C++ file
        full_code = code + "\n" + test_report
        # Write combined C++ code to a temporary file
        with open(cpp_file, "w") as f:
            f.write(full_code)
        
        try:
            # Compile the C++ code
            compile_result = subprocess.run([
                "g++", cpp_file, "-o", exe_file, "-std=c++17", "-O2"
            ], capture_output=True, text=True, timeout=10)
            
            if compile_result.returncode != 0:
                return f"Compilation failed: {compile_result.stderr}"
            
            # Run the compiled program
            run_result = subprocess.run([
                exe_file
            ], capture_output=True, text=True, timeout=5)
            
            if run_result.returncode != 0:
                return f"Runtime error: {run_result.stderr}"
            
            # return "Code Test Passed.\n" + run_result.stdout.strip()
            return "Code Test Passed."
        
        except subprocess.TimeoutExpired:
            return "Execution timed out."
        except Exception as e:
            return f"Execution failed: {e}"

def reliability_guard(maximum_memory_bytes = None):
    """
    This disables various destructive functions and prevents the generated code
    from interfering with the test (e.g. fork bomb, killing other processes,
    removing filesystem files, etc.)

    WARNING
    This function is NOT a security sandbox. Untrusted code, including, model-
    generated code, should not be blindly executed outside of one. See the 
    Codex paper for more information about OpenAI's code sandbox, and proceed
    with caution.
    """

    if maximum_memory_bytes is not None:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (maximum_memory_bytes, maximum_memory_bytes))
        resource.setrlimit(resource.RLIMIT_DATA, (maximum_memory_bytes, maximum_memory_bytes))
        if not platform.uname().system == 'Darwin':
            resource.setrlimit(resource.RLIMIT_STACK, (maximum_memory_bytes, maximum_memory_bytes))

    faulthandler.disable()

    import builtins
    builtins.exit = None
    builtins.quit = None

    import os
    os.environ['OMP_NUM_THREADS'] = '1'

    os.rmdir = None
    os.chdir = None

    import shutil
    shutil.rmtree = None
    shutil.move = None
    shutil.chown = None

    import subprocess
    subprocess.Popen = None  # type: ignore

    __builtins__['help'] = None

    import sys
    sys.modules['ipdb'] = None
    sys.modules['joblib'] = None
    sys.modules['resource'] = None
    sys.modules['psutil'] = None
    sys.modules['tkinter'] = None
    
@contextlib.contextmanager
def time_limit(seconds: float):
    def signal_handler(signum, frame):
        raise TimeoutException("Timed out!")
    signal.setitimer(signal.ITIMER_REAL, seconds)
    signal.signal(signal.SIGALRM, signal_handler)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


@contextlib.contextmanager
def swallow_io():
    stream = WriteOnlyStringIO()
    with contextlib.redirect_stdout(stream):
        with contextlib.redirect_stderr(stream):
            with redirect_stdin(stream):
                yield


@contextlib.contextmanager
def create_tempdir():
    with tempfile.TemporaryDirectory() as dirname:
        with chdir(dirname):
            yield dirname
            
class TimeoutException(Exception):
    pass


class WriteOnlyStringIO(io.StringIO):
    """ StringIO that throws an exception when it's read from """

    def read(self, *args, **kwargs):
        raise IOError

    def readline(self, *args, **kwargs):
        raise IOError

    def readlines(self, *args, **kwargs):
        raise IOError

    def readable(self, *args, **kwargs):
        """ Returns True if the IO object can be read. """
        return False


class redirect_stdin(contextlib._RedirectStream):  # type: ignore
    _stream = 'stdin'


@contextlib.contextmanager
def chdir(root):
    if root == ".":
        yield
        return
    cwd = os.getcwd()
    os.chdir(root)
    try:
        yield
    except BaseException as exc:
        raise exc
    finally:
        os.chdir(cwd)