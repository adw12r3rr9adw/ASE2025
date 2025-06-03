import os
import gzip
import json
import openai
import jsonlines
from ipdb import set_trace  

from typing import List

openai.api_key = ""
openai.api_base = ""

IMPORT_HEADER = "#include <bits/stdc++.h>"+"\n"

def prepare_function_from_seed(dataset_type, prompt, seed, entry_point):
    if dataset_type in ["HumanEval", "MBPP"]:
        if (prompt in seed) or (entry_point in seed):
            cur_func_impl = seed
        else:
            cur_func_impl = prompt + "\n" + seed
        if not cur_func_impl.strip().endswith("}"):
            cur_func_impl += "\n}"
        funcs = get_function(prompt) 
        seed_funcs = [func[0] for func in get_function(seed)] 
        for func in funcs:
            if func[0] not in seed_funcs:
                cur_func_impl = func[1] + "\n" + cur_func_impl  # 

    elif dataset_type in ["TransCoder"]:
        cur_func_impl = seed
    if IMPORT_HEADER not in cur_func_impl:
        cur_func_impl = IMPORT_HEADER + " " +cur_func_impl
    assert isinstance(cur_func_impl, str)
    return cur_func_impl

def fix_func_impl_comments(func_impl: str, prompt: str, entry) -> str:
    if prompt.find('\"\"\"') != -1:
        comments = prompt.split('\"\"\"')[1]
    elif prompt.find('\'\'\'') != -1:
        comments = prompt.split('\'\'\'')[1]
    func_impl_lines = func_impl.split('\n')
    for i, line in enumerate(func_impl_lines):
        if line.startswith('def') and entry in line:
            break
    func_impl_lines.insert(i+1, '    \"\"\"' + comments + '\"\"\"')
    return '\n'.join(func_impl_lines)

def insert_comment(func_impl: str, comment: str, entry: str) -> str:
    func_impl_lines = func_impl.split('\n')
    for i, line in enumerate(func_impl_lines):
        if line.startswith('def ' + entry + '('):
            break
    func_impl_lines.insert(i + 1, '    \"\"\"' + comment + '\"\"\"')
    return '\n'.join(func_impl_lines)

def remove_comment(old_block: List[str]) -> str:
    new_block = []
    old_block_lines = old_block.split('\n')
    for line in old_block_lines:
        if line.lstrip().startswith('#'):
            continue
        new_block.append(line)
    if len(new_block) == 1:
        return new_block[0]
    else:
        return '\n'.join(new_block)

def extrace_comment(prompt: str) -> str:
    if prompt.find('\"\"\"') != -1:
        comments = prompt.split('\"\"\"')[-2]
    elif prompt.find('\'\'\'') != -1:
        comments = prompt.split('\'\'\'')[-2]
    return comments

def find_comment(func_impl: str, entry: str ) -> bool:
    func_impl_lines = func_impl.split('\n')
    for i, line in enumerate(func_impl_lines):
        if line.startswith('def ' + entry + "("):
            break
    func_body = "\n".join(func_impl_lines[i:])
    if func_body.find('\"\"\"') != -1 or func_body.find('\'\'\'') != -1:
        return True
    return False

def get_function(prompt):
    lines = prompt.split('\n')
    cur_func = ""
    funcs = []
    for i, l in enumerate(lines):
        if l.startswith("def "):
            if cur_func == "":
                cur_func = l
            else:
                funcs.append([func_name, cur_func])
                cur_func = l
            func_name = l.split("def ")[1].split("(")[0]
        elif cur_func != "":
            cur_func += "\n" + l
    return funcs

def convert_comment(translation_prompt):
    cpp_prog = translation_prompt.split("[c++]")[1].split("[python]")[0]
    commented_prog = "\'\'\'\nC++ Implementation\n" + cpp_prog.strip() + "\n\'\'\'\n"
    return commented_prog

def make_printv(verbose: bool):
    def print_v(*args, **kwargs):
        if verbose:
            kwargs["flush"] = True
            print(*args, **kwargs)
        else:
            pass
    return print_v


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

def read_jsonl_map(path: str) -> List[dict]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"File `{path}` does not exist.")
    elif not path.endswith(".jsonl"):
        raise ValueError(f"File `{path}` is not a jsonl file.")
    items = {}
    with jsonlines.open(path) as reader:
        for item in reader:
            items[item['task_id']] = item
    return items

def write_jsonl(path: str, data: List[dict], append: bool = False):
    with jsonlines.open(path, mode='a' if append else 'w') as writer:
        for item in data:
            writer.write(item)


def read_jsonl_gz(path: str) -> List[dict]:
    if not path.endswith(".jsonl.gz"):
        raise ValueError(f"File `{path}` is not a jsonl.gz file.")
    with gzip.open(path, "rt") as f:
        data = [json.loads(line) for line in f]
    return data


def replace_seed_test(item, items_seed, items_test):
    if item['task_id'] in items_seed:
        item['seed'] = items_seed[item['task_id']]['solution']
        if 'is_passing' in items_seed[item['task_id']]:
            item['is_passing'] = items_seed[item['task_id']]['is_passing']
        else:
            item['is_passing'] = False
    else:
        item['seed'] = ""
    return item


def enumerate_resume(dataset, results_path, seedfile = None, testfile = None):
    items_seed = {}
    items_test = {}
    if seedfile is not None:
        items_seed = read_jsonl_map(seedfile)
    if testfile is not None:
        items_test = read_jsonl_map(testfile)
    
    if not os.path.exists(results_path):
        for i, item in enumerate(dataset):
            item = replace_seed_test(item, items_seed, items_test)
            yield i, item
    else:
        count = 0
        exist_items = []
        with jsonlines.open(results_path) as reader:
            for item in reader:
                exist_items.append(item['task_id'])

        for i, item in enumerate(dataset):
            if item['task_id'] in exist_items:
                continue
            item = replace_seed_test(item, items_seed, items_test)
            yield i, item


def resume_success_count(dataset) -> int:
    count = 0
    for item in dataset:
        if "is_solved" in item and item["is_solved"]:
            count += 1
    return count

def count_solved(logpath) -> float:
    solved = 0
    count = 0
    dataset = open(logpath, "r")
    for l in dataset:
        item = json.loads(l)
        count += 1
        if "is_solved" in item and item["is_solved"]:
            solved += 1
    return float(solved) / count