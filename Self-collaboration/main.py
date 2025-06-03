import os
import copy
import json
import argparse
import tqdm

from ipdb import set_trace
from session import Session
from datasets import load_dataset, load_from_disk
from utils import prompt_split_humaneval, find_method_name, code_split, build_test_method, read_jsonl, cpp_prompt_split

parser = argparse.ArgumentParser()
parser.add_argument('--dataset', type=str, default='humaneval')
parser.add_argument('--lang', type=str, default='cpp')
parser.add_argument('--input_path', type=str)
parser.add_argument('--output_path', type=str, default='output.jsonl')

parser.add_argument('--signature', action='store_true')
parser.add_argument('--model', type=str, default='gpt-3.5-turbo-0301')
parser.add_argument('--max_round', type=int, default=2)

parser.add_argument('--max_tokens', type=int, default=512) 
parser.add_argument('--majority', type=int, default=1)
parser.add_argument('--temperature', type=float, default=0.0)
parser.add_argument('--top_p', type=float, default=0.95)

parser.add_argument('--fail_list', type=list, default=[])
parser.add_argument('--append', default=True, action='store_true')
parser.add_argument('--verbose', action='store_true')
parser.add_argument("--timeout", type=float, default=10, help="how many seconds to wait during execution for each test case")

parser.add_argument('--start_id', type=int, default=0)
parser.add_argument('--end_id', type=int, default=None)

args = parser.parse_args()

def extract_task_by_id(jsonl_path, target_task_id):
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            item = json.loads(line)
            if item.get("task_id") == target_task_id:
                return item
    return None

if __name__ == '__main__':
    from roles.rule_descriptions_actc import TEAM, ANALYST, CPP_DEVELOPER, TESTER

    OUTPUT_PATH = args.output_path

    dataset = read_jsonl(args.input_path)
    processed_task_ids = set()
    if args.append and os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH, 'r') as f:
            for line in f:
                try:
                    task_data = json.loads(line.strip())
                    processed_task_ids.add(task_data['task_id'])
                except json.JSONDecodeError:
                    continue

    with open(OUTPUT_PATH, 'a' if args.append else 'w+') as f:
        pbar = tqdm.tqdm(dataset, total=len(dataset))
        for idx, task in enumerate(pbar):
            init_code = extract_task_by_id(args.input_path, task['task_id'])['completion']
            task_id_num = int(task['task_id'].split('/')[-1])
            if args.start_id is not None and task_id_num < args.start_id:
                continue
            if args.end_id is not None and task_id_num >= args.end_id:
                continue
            if task['task_id'] in processed_task_ids:
                print(f"Task {task['task_id']} already processed, skipping...")
                continue
            if True:
                method_name = task['entry_point']
                before_func, signature, intent, public_test_case = cpp_prompt_split(task['prompt'], method_name)
                args.signature = True
                if args.signature:
                    intent = task['prompt']

            try:
                session = Session(TEAM, ANALYST, CPP_DEVELOPER, TESTER, requirement=intent, model=args.model, majority=args.majority, 
                                 max_tokens=args.max_tokens, temperature=args.temperature, 
                                 top_p=args.top_p, max_round=args.max_round, before_func=before_func,init_code=init_code)
                print(f"Task {task['task_id']} start...")
                code, session_history = session.run_session()

            except RuntimeError as e:
                print(str(e))
                print("task-%d fail" % (task['task_id']))
                args.fail_list.append(task['task_id'])
                continue

            if code == "error":
                continue

            solution = {
                'task_id': task['task_id'],
                'prompt': before_func + "\n",
                'entry_point': task['entry_point'],
                'completion': code,
                'session_history': session_history,
            }
            f.write(json.dumps(solution) + '\n')
            f.flush()

            print(f"Task {task['task_id']} done...")