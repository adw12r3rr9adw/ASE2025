import logging
import os
import argparse
import json
import random
from collections import defaultdict
import queue
import threading
from typing import Callable, Any, List, Dict, Optional
from utils import load_jsonl, save_jsonl, safe_filename
from scoring_strategy_constraints import scoring_strategy_constraints
from scoring_strategy_similarity import scoring_strategy_similarity

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def execute_with_timeout(
    func: Callable[..., Any], 
    timeout_seconds: int = 15, 
    *args, 
    **kwargs
) -> Optional[Any]:
    result_queue = queue.Queue()
    exception_queue = queue.Queue()

    def wrapper():
        try:
            result = func(*args, **kwargs)
            result_queue.put(result)
        except Exception as e:
            exception_queue.put(e)

    thread = threading.Thread(target=wrapper)
    thread.daemon = True
    thread.start()
    thread.join(timeout=timeout_seconds)

    if thread.is_alive():
        logger.error(f"Function {func.__name__} timed out after {timeout_seconds} seconds.")
        return None
    if not exception_queue.empty():
        exception = exception_queue.get()
        logger.error(f"Function {func.__name__} raised an exception: {str(exception)}")
        return None
    return result_queue.get() if not result_queue.empty() else None

def select_code_sample(
    task_id: str, 
    code_samples: List[Dict[str, Any]], 
    output_dir: str, 
    strategy: str, 
    debug_mode: bool, 
    timeout_seconds: int = 15
) -> Dict[str, Any]:
    print(f"Processing task {task_id} with {len(code_samples)} code samples.")
    safe_task_id = safe_filename(task_id)
    res_dir = os.path.join(output_dir, safe_task_id, 'res')

    if not code_samples:
        print(f"No available code samples. Selecting one at random.")
        return random.choice(code_samples)

    def select_strategy():
        try:
            if strategy == 'constraints':
                selected_sample = scoring_strategy_constraints(code_samples, res_dir, debug_mode)
                print(f"Selected by constraint-based strategy: {selected_sample['unique_id']}")
            elif strategy == 'similarity':
                selected_sample = scoring_strategy_similarity(code_samples)
                print(f"Selected by similarity-based strategy: {selected_sample['unique_id']}")
            elif strategy == 'random':
                selected_sample = random.choice(code_samples)
                print(f"Selected randomly: {selected_sample['unique_id']}")
            else:
                selected_sample = random.choice(code_samples)
                print(f"Defaulting to random selection: {selected_sample['unique_id']}")
            return selected_sample
        except Exception as e:
            logger.error(f"Error during strategy selection: {str(e)}")
            raise

    selected_sample = execute_with_timeout(
        select_strategy, 
        timeout_seconds=timeout_seconds
    )

    if selected_sample is None:
        logger.error(f"Strategy {strategy} failed or timed out. Falling back to random selection.")
        selected_sample = random.choice(code_samples)
        print(f"Fallback random selection: {selected_sample['unique_id']}")

    return selected_sample

def main():
    parser = argparse.ArgumentParser(description="Select the best code sample (supports incremental selection).")
    parser.add_argument('--debug_mode', action='store_true')
    parser.add_argument('--debug_list', type=str, default="")
    parser.add_argument('--dataset', type=str, default="mbpp")
    parser.add_argument('--model', type=str, default="4omini")
    parser.add_argument('--strategy', type=str, default="constraints", choices=['random', 'similarity', 'constraints'])
    parser.add_argument('--output_dir', type=str, default="output")
    parser.add_argument('--flag', type=str, default="")
    parser.add_argument('--top_n', type=int, default=10, help="Number of top-N code samples to select from for each task.")
    args = parser.parse_args()

    debug_mode = args.debug_mode
    debug_list = set(args.debug_list.split()) if args.debug_list else set()
    output_dir = os.path.join(args.output_dir, args.dataset, args.model)
    os.makedirs(output_dir, exist_ok=True)

    merged_file = os.path.join('data', args.dataset, args.model, f"merged_{args.model}.jsonl")
    samples_file = os.path.join('data', args.dataset, args.model, f"samples_{args.model}.jsonl")
    selected_file = os.path.join('data', args.dataset, args.model, f"selected_codes_{args.dataset}_{args.model}_{args.strategy}_{args.flag}.jsonl")

    try:
        merged_data = load_jsonl(merged_file)
        samples_data = load_jsonl(samples_file)
    except Exception as e:
        logger.error(f"Failed to load data: {e}")
        return

    if os.path.exists(selected_file):
        selected_results = load_jsonl(selected_file)
        selected_task_ids = set([item['task_id'] for item in selected_results])
    else:
        selected_results = []
        selected_task_ids = set()

    logger.info(f"{len(selected_task_ids)} tasks already selected. Continuing with incremental selection.")

    task_code_list = defaultdict(list)
    task_counters = {}
    for idx, (merged_item, sample_item) in enumerate(zip(merged_data, samples_data)):
        task_id = merged_item['task_id']
        if debug_mode and task_id not in debug_list:
            continue
        safe_task_id = safe_filename(task_id)
        task_counters[safe_task_id] = task_counters.get(safe_task_id, 0) + 1
        unique_id = f"{safe_task_id}_{task_counters[safe_task_id]}"

        task_code_list[task_id].append({
            'task_id': task_id,
            'code': merged_item['code'],
            'completion': sample_item['completion'],
            'index': idx,
            'unique_id': unique_id
        })

    top_n = args.top_n
    for task_id in task_code_list:
        task_code_list[task_id] = task_code_list[task_id][:top_n]

    code_result_file = os.path.join('data', args.dataset, args.model, f"samples_{args.model}.jsonl_results.jsonl")

    for task_id, code_samples in task_code_list.items():
        if task_id in selected_task_ids:
            logger.info(f"Task {task_id} has already been processed. Skipping.")
            continue
        res_path = os.path.join(output_dir, safe_filename(task_id), 'res')
        txt_files = [f for f in os.listdir(res_path) if f.endswith('.txt')] if os.path.exists(res_path) else []
        if args.strategy == 'random':
            select_strategy = 'random'
        elif len(txt_files) != top_n or any(os.stat(os.path.join(res_path, f)).st_size == 0 for f in txt_files):
            select_strategy = 'similarity'
        else:
            select_strategy = args.strategy

        selected_sample = select_code_sample(task_id, code_samples, output_dir, strategy=select_strategy, debug_mode=debug_mode)

        selected_results.append({
            'task_id': task_id,
            'completion': selected_sample['completion'],
            'unique_id': selected_sample['unique_id'],
            'index': selected_sample['index']
        })
        logger.info(f"Task {task_id} selected code sample {selected_sample['unique_id']}")

        save_jsonl(selected_results, selected_file)

    logger.info(f"All tasks processed. Results saved to: {selected_file}")

if __name__ == '__main__':
    main()
