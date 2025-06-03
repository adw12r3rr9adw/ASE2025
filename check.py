import json
from collections import defaultdict


file_path = 'data/samples_4o.jsonl_results.jsonl'

task_results = defaultdict(list)

with open(file_path, 'r') as file:
    for line in file:
        entry = json.loads(line)
        task_id = entry['task_id']
        passed = entry['passed']
        task_results[task_id].append(passed)
mixed_results_tasks = []
failed_results_tasks = []
all_failed_tasks = []

for task_id, results in task_results.items():
    if True in results and False in results:
        mixed_results_tasks.append(task_id)
    if False in results: 
        failed_results_tasks.append(task_id)
    if all(result is False for result in results):
        all_failed_tasks.append(task_id)


print("Task IDs with both passed and failed results:")
for task_id in mixed_results_tasks:
    print(task_id)

print("\nTask IDs with any failed results:")
for task_id in failed_results_tasks:
    print(task_id)

print("\nTask IDs with all failed results:")
for task_id in all_failed_tasks:
    print(task_id)