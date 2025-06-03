import re
import os
import random
import claripy
from ipdb import set_trace
from typing import List, Dict
import pickle


def parse_constraints_from_pkl(file_path: str) -> List[List[claripy.ast.Bool]]:
    set_trace()
    try:
        with open(file_path, 'rb') as f:
            return pickle.load(f)
    except FileNotFoundError:
        print(f"constraints file not exist {file_path}")
        return []
    except Exception as e:
        print(f"parse_constraints_error:{e}")
        return []
    
paths_info = parse_constraints_from_pkl("example.pkl")