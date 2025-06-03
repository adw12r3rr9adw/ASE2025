# utils.py
import os
import logging
logger = logging.getLogger(__name__)
logger.propagate = True
from angr import project
import re
import cxxfilt
import pickle
import time
import json
from ipdb import set_trace

def print_paths_info(paths_info, output_file_txt, output_file_pkl):
    if output_file_txt:
        try:
            with open(output_file_txt, 'w', encoding='utf-8') as f:
                for idx, path_info in enumerate(paths_info):
                    f.write(f"=== Path {idx + 1} ===\n")
                    if len(path_info['ret_expr']) != 0:
                        f.write(f"Return: {path_info['ret_expr']}\n")
                    f.write("Constraints:\n")
                    for constraint in path_info['constraints']:
                        f.write(f"{constraint.shallow_repr()}\n")
                    f.write("\n")
                    f.flush()
                    if f.tell() > 5 * 1024 * 1024:  # Exceeds 5MB
                        print("File too large, stopping write.")
                        break
        except IOError as e:
            print(f"Failed to write constraint text file: {e}")

    if output_file_pkl:
        try:
            with open(output_file_pkl, 'wb') as f:
                pickle.dump(paths_info, f)
        except IOError as e:
            print(f"Failed to write binary constraint file: {e}")

def extract_function_signature(code, function_name):
    lines = code.split('\n')

    pattern = re.compile(r'''
        ^\s*
        ([\w:<>*&\s]+?)      
        \s+
        ([\w:]+)        
        \s*
        \(
            ([^)]*)  
        \)
        \s*(const)?    
        \s*(\{)?   
        \s*$
    ''', re.VERBOSE)

    for line in lines:
        line = line.strip()

        if not line or line.startswith(('#', '/', '*')):
            continue
        match = pattern.search(line)
        if match:
            return_type = match.group(1).strip()
            current_function_name = match.group(2).strip()
            params = match.group(3).strip()

            if current_function_name == function_name:
                args_types = []
                for param in params.split(','):
                    param = param.strip()
                    if param:
                        param = param.split('=')[0].strip()
                        param = re.sub(r'\s*\w+$', '', param)
                        args_types.append(param.strip())

                return return_type, args_types

    raise ValueError(f"No function signature found for function name: {function_name}")

def load_binary(binary_path, auto_load_libs=False):
    project = angr.Project(binary_path, auto_load_libs=auto_load_libs)
    return project

def parse_map_file(map_file):
    func_addr_dict = {}
    with open(map_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue 
            if line.startswith('.text'):
                continue 
            elif line.startswith('0x') or line.startswith('0'):
                parts = line.strip().split()
                if len(parts) >= 2:
                    addr_str = parts[0]
                    name = ' '.join(parts[1:])
                    try:
                        addr = int(addr_str, 16)
                        try:
                            demangled_name = cxxfilt.demangle(name)
                            func_addr_dict[demangled_name] = addr
                        except Exception:
                            func_addr_dict[name] = addr
                    except ValueError:
                        continue
        return func_addr_dict

def get_function_address(func_addr_dict, function_name):
    for name, addr in func_addr_dict.items():
        if function_name == name:
            print(f"Found function: {name}, address: {hex(addr)}")
            return hex(addr)
        elif function_name in name:
            return hex(addr)
    raise ValueError(f"Function {function_name} not found.")

def safe_filename(name):
    return re.sub(r'[<>:"/\\|?*]', '_', name)

def load_jsonl(file_path):
    data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                data.append(json.loads(line))
        logger.info(f"Successfully loaded file: {file_path}")
    except Exception as e:
        logger.error(f"Failed to load file {file_path}: {e}")
        raise
    return data

def save_jsonl(data, file_path):
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in data:
                f.write(json.dumps(item, ensure_ascii=False) + '\n')
    except Exception as e:
        logger.error(f"Failed to save file {file_path}: {e}")
        raise
