import json
import os
import logging

logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(message)s')

def check_file_exists(filename):
    if not os.path.exists(filename):
        raise FileNotFoundError(f"file{filename}not found.")

def get_task_ids_by_status(filename, status):
    task_ids = set()
    with open(filename, 'r', encoding='utf-8') as f:
        for line_number, line in enumerate(f, 1):
            if not line.strip():
                continue 
            try:
                data = json.loads(line)
                if data.get('passed') == status:
                    task_ids.add(data['task_id'])
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON in {filename}, line {line_number}: {e}")
                logging.error(f"Problematic line: {line}")
                continue
    return task_ids

def print_sorted_set(title, data):
    sorted_data = sorted(data)
    print(f"{title} (count:{len(sorted_data)}): {sorted_data}")

def main():
    dataset = "mbpp"
    model = "4o"
    strategy = "constraints"
    flag = "test1"
    results_file = os.path.join('data', dataset, model, f"selected_codes_{dataset}_{model}_{strategy}_{flag}.jsonl_results.jsonl") 
    sample_file = os.path.join('data', dataset, model, f"samples_{model}.jsonl_results.jsonl")  

    check_file_exists(results_file)
    check_file_exists(sample_file)

    failed_tasks_constraints = get_task_ids_by_status(results_file, False)

    passed_tasks_in_sample = get_task_ids_by_status(sample_file, True)

    failed_but_have_passing_code = failed_tasks_constraints & passed_tasks_in_sample

    print_sorted_set(failed_but_have_passing_code)

if __name__ == "__main__":
    main()