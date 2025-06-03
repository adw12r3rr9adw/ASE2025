import json
import re

def read_jsonl(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return [json.loads(line) for line in file]

def extract_task_id(task_id):
    match = re.search(r'\d+', task_id)
    return int(match.group()) if match else float('inf')

def sort_jsonl_by_task_id(data):
    return sorted(data, key=lambda x: extract_task_id(x['task_id']))

def write_jsonl(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as file:
        for entry in data:
            file.write(json.dumps(entry, ensure_ascii=False) + '\n')

def main():
    input_file = 'Self-collaboration-Code-Generation/humaneval_output_gpt-4o-mini-2024-07-18.jsonl' 
    output_file = 'sorted_output.jsonl' 
    
    data = read_jsonl(input_file)
    sorted_data = sort_jsonl_by_task_id(data)
    write_jsonl(output_file, sorted_data)
    
    print(f'Sorted JSONL file saved as {output_file}')

if __name__ == '__main__':
    main()
