import json

def inject_entry_point(python_tasks_path, cpp_tasks_path, output_path):
    with open(python_tasks_path, 'r', encoding='utf-8') as f:
        python_tasks = [json.loads(line) for line in f]

    with open(cpp_tasks_path, 'r', encoding='utf-8') as f:
        cpp_tasks = [json.loads(line) for line in f]

    py_id_to_entry = {task['task_id']: task['entry_point'] for task in python_tasks if 'entry_point' in task}

    for task in cpp_tasks:
        task_id = task.get('task_id')
        if task_id in py_id_to_entry:
            task['entry_point'] = py_id_to_entry[task_id]

    with open(output_path, 'w', encoding='utf-8') as f:
        for task in cpp_tasks:
            f.write(json.dumps(task, ensure_ascii=False) + '\n')


inject_entry_point('HumanEval_py.jsonl', 'humaneval.jsonl', 'updated_humaneval.jsonl')
