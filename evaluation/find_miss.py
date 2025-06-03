import json

def load_task_ids(file_path):
    task_ids = set()
    with open(file_path, 'r') as f:
        for line in f:
            obj = json.loads(line)
            task_ids.add(obj['task_id'])
    return task_ids

def find_extra_tasks(file1, file2):
    task_ids_1 = load_task_ids(file1)
    task_ids_2 = load_task_ids(file2)

    extra = task_ids_2 - task_ids_1
    return sorted(extra)

if __name__ == "__main__":
    file1 = ""
    file2 = ""

    extra_task_ids = find_extra_tasks(file1, file2)
    print(f"Tasks in {file2} but not in {file1}:")
    for task_id in extra_task_ids:
        print(task_id)
