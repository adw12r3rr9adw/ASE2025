import json
import re
import ast
import time
import difflib
import copy
import os
import jsonlines
from typing import List


def code_truncate_regex(code):
    code_regex = r"```(.*?|)\n(?P<code>.*?)```"
    match = re.search(code_regex, code, re.DOTALL)
    code = match.group("code") if match else ""
    return code
    
def code_truncate(response):
    code = code_truncate_regex(response)
    if code == "":
        generation = response[response.find("def"):]
        tem = [s for s in generation.split('\n\n') if 'def ' in s or s[:1] == ' ']
        code = '\n\n'.join(tem).strip('```').strip()
    return code

def prompt_split_humaneval(prompt, method_name):
    prompt = prompt.strip()
    prompt = prompt.replace("\r\n", "\n")
    before_func = prompt[:prompt.rfind("def ")]
    code = prompt[prompt.rfind("def "):]

    comment_start_1 = re.search("\"\"\"", code)
    comment_start_2 = re.search("\'\'\'", code)
    if comment_start_1:
        comment_start = comment_start_1.end()
    elif comment_start_2:
        comment_start = comment_start_2.end()


    example_start_1 = re.search("[eE]xample(:)?", code)
    example_start_2 = re.search("[fF]or [eE]xamble(:)?", code)
    example_start_3 = re.search(">>>", code)
    example_start_4 = re.search(method_name+"\(.+\)", code[comment_start:])


    if example_start_1:
        comment = code[comment_start:example_start_1.start()]
        example = code[example_start_1.start():-4]
    elif example_start_2:
        comment = code[comment_start:example_start_2.start()]
        example = code[example_start_2.start():-4]
    elif example_start_3:
        comment = code[comment_start:example_start_3.start()]
        example = "Example:\n"+code[example_start_3.start():-4]
    elif example_start_4:
        comment = code[comment_start:example_start_4.start()+comment_start]
        example = "Example:\n"+code[example_start_4.start()+comment_start:-4]
    else:
        comment = code[comment_start:-4]
        example = ""
    comment = comment.strip().replace("\n", " ")
    comment = re.sub("\s+", " ", comment)

    example = re.sub("\n(\s)*","\n\t",example)
    test_case = "\t"+example.strip()
    signature = code[:code.index("\n")+1]

    return before_func, signature, comment, test_case

def cpp_prompt_split(prompt, method_name):
    prompt = prompt.strip().replace("\r\n", "\n")
    
    block_comment_match = re.search(r'/\*(.*?)\*/', prompt, re.DOTALL)
    if block_comment_match:
        block_comment = block_comment_match.group(1).strip()
        example_match = re.search(r'>>>', block_comment)
        if example_match:
            comment_text = block_comment[:example_match.start()].strip()
            example_text = block_comment[example_match.start():].strip()
        else:
            comment_text = block_comment
            example_text = ""
    else:
        comment_text = ""
        example_text = ""
    
    comment_text = re.sub(r'\s+', ' ', comment_text)
    
    if example_text:
        if not example_text.lower().startswith("example"):
            example_text = "Example:\n" + example_text
        test_case = "\t" + example_text.replace("\n", "\n\t")
    else:
        test_case = ""
    
    func_index = prompt.find(method_name + "(")
    if func_index == -1:
        signature = ""
        before_func = prompt
    else:
        line_start = prompt.rfind("\n", 0, func_index)
        if line_start == -1:
            line_start = 0
        else:
            line_start += 1
        line_end = prompt.find("\n", func_index)
        if line_end == -1:
            line_end = len(prompt)
        signature = prompt[line_start:line_end].strip()
        before_func = prompt[:line_start]
    
    return before_func, signature, comment_text, test_case


def build_test_method(test_list, test_imports, method_name):
    if test_imports:
        test_imports = "\n".join(test_imports)
        test_method = test_imports + "\n"
    else:
        test_method = ""
    test_method = "def check(" + method_name + "):\n"
    if len(test_list) == 0:
        return test_method + "\treturn True" + "\n"
    for test in test_list:
        test_method += '\t' + test + "\n"
    return test_method.strip("\n")

def find_method_name(code, lang="python"):
    try:
        parsed = ast.parse(code)
        function_defs = [node for node in parsed.body if isinstance(node, ast.FunctionDef)]
        if function_defs:
            if len(function_defs) == 1:
                method_name = function_defs[0].name
            else:
                method_name = function_defs[-1].name if function_defs[-1].name != "main" else function_defs[-2].name
        else:
            method_name = None
    except:
        method_name = None

    return method_name


def code_split(func):
    '''
    Split code into signature, comment and function body
    '''
    func = func.replace("\r\n", "\n")
    before_func = func[:func.rfind("def ")]
    code = func[func.rfind("def "):]

    is_comment = False
    comments = []
    
    statements = code.split("\n")
    for s_idx, s in enumerate(statements):
        s = s.strip()
        if s.startswith("def"):
            signature = statements[:s_idx+1]
            method_name = s.split("def ")[1].split("(")[0]
            func_body_idx = s_idx+1
            tmp_statement = statements[func_body_idx].strip()
            if not tmp_statement.startswith("'''"):
                break
        elif s.startswith("'''") and not is_comment:
            is_comment = True

        elif is_comment:
            if s.startswith("'''"):
                is_comment = False
                func_body_idx = s_idx+1
                break
            comments.append(s)
    func_body = statements[func_body_idx:]
    return method_name, "\n".join(signature), "\n".join(comments), "\n".join(func_body), before_func

def construct_system_message(requirement, role, team=''):
    if team == '':
        system_message = "The requirement from users is: \n{'requirement':\n"  +  "'"+ requirement.replace('\n\n','\n').strip(".") + "'\n}\n\n" + role
    else:
        system_message = team + '\n '+ \
                    "The requirement from users is: \n{'requirement':\n"  +  "'"+ requirement.replace('\n\n','\n').strip(".") + "'\n}\n\n" + \
                    role
                
    return system_message

def read_jsonl(path: str) -> List[dict]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"File `{path}` does not exist.")
    elif not path.endswith(".jsonl"):
        raise ValueError(f"File `{path}` is not a jsonl file.")
    items = []
    with jsonlines.open(path) as reader:
        for item in reader:
            items += [item]
    return items
    