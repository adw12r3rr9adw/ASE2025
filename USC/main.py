import argparse
import json
import os
from collections import defaultdict
from openai import OpenAI
import time

MODEL_API_KEYS = {
    'deepseek-v3': '',
    'gemini-2.0-flash-thinking-exp-01-21': '',
    'gpt-4o': '',
    'gpt-4o-mini': '',
}

API_BASE_URL = ""

def load_jsonl(file_path):
    data = []
    if not os.path.exists(file_path):
        return data 
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            data.append(json.loads(line.strip()))
    return data

def group_codes_by_task_id(codes_data):
    grouped_codes = defaultdict(list)
    task_id_order = []
    for item in codes_data:
        if item['task_id'] not in grouped_codes:
            task_id_order.append(item['task_id'])
        grouped_codes[item['task_id']].append(item)
    return grouped_codes, task_id_order

def get_problem_description(problem_data, task_id):
    for problem in problem_data:
        if problem['task_id'] == task_id:
            return problem['prompt']
    return None

def call_llm_for_selection(model_name, api_key, prompt, code_candidates):
    client = OpenAI(
        base_url=API_BASE_URL,
        api_key=api_key,
    )

    formatted_candidates = []
    for i, candidate in enumerate(code_candidates):
        formatted_candidates.append(f"Response {i+1}:\n```cpp\n{candidate['code']}\n```")
    
        full_prompt = (
        f"You have generated the following responses to the question:\n"
        f"---BEGIN QUESTION---\n{prompt}\n---END QUESTION---\n\n"
        f"---BEGIN RESPONSES---\n"
        + "\n\n".join(formatted_candidates) +
        f"\n---END RESPONSES---\n\n"
        f"Select the most consistent response based on majority consensus. "
        f"Output only the selected code block, including the ```cpp``` and ``` markers, and nothing else."
    )

    messages = [
        {"role": "user", "content": full_prompt}
    ]

    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=0.0,  
            max_tokens=2048,
        )
        selected_code_content = response.choices[0].message.content
        if "```cpp" in selected_code_content and "```" in selected_code_content:
            start = selected_code_content.find("```cpp") + len("```cpp")
            end = selected_code_content.find("```", start)
            return selected_code_content[start:end].strip()
        return selected_code_content.strip()
    except Exception as e:
        print(f"Error calling LLM API for task: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Perform code selection using LLM self-consistency.")
    parser.add_argument('--dataset', type=str, required=True, help="Dataset name (e.g., humaneval, mbpp).")
    parser.add_argument('--model', type=str, required=True, help="Full model name (e.g., deepseek-v3, gpt-4o-mini).")
    parser.add_argument('--input_path', type=str, required=True, help="Path to the merged input JSONL file (multiple candidates per task_id).")
    parser.add_argument('--output_path', type=str, required=True, help="Path to save the output JSONL file (selected code).")
    parser.add_argument('--lang', type=str, default='cpp', help="Programming language (e.g., cpp, python).") # Not directly used in prompt, but good to have

    args = parser.parse_args()

    problem_file_path = f"/USC/evaluation/{args.dataset}.jsonl"

    print(f"Loading problem data from: {problem_file_path}")
    problem_data = load_jsonl(problem_file_path)
    if not problem_data:
        print(f"Error: Could not load problem data from {problem_file_path}. Exiting.")
        return

    print(f"Loading input code candidates from: {args.input_path}")
    all_code_candidates = load_jsonl(args.input_path)
    if not all_code_candidates:
        print(f"Error: No code candidates found in {args.input_path}. Exiting.")
        return

    grouped_candidates, task_id_order = group_codes_by_task_id(all_code_candidates)
    
    print(f"Checking for existing results in {args.output_path} to resume...")
    existing_outputs = load_jsonl(args.output_path)
    processed_task_ids = {item['task_id'] for item in existing_outputs}
    print(f"Found {len(processed_task_ids)} tasks already processed.")

    api_key = MODEL_API_KEYS.get(args.model)
    if not api_key:
        print(f"Error: API key not found for model '{args.model}'. Please add it to MODEL_API_KEYS.")
        return
    
    output_dir = os.path.dirname(args.output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(args.output_path, 'a', encoding='utf-8') as f_out:
        for i, task_id in enumerate(task_id_order):
            if task_id in processed_task_ids:
                print(f"Skipping task {i+1}/{len(task_id_order)}: {task_id} (already processed).")
                continue
            
            candidates_for_task = grouped_candidates[task_id]
            if len(candidates_for_task) != 10:
                print(f"Warning: Task '{task_id}' has {len(candidates_for_task)} candidates, expected 10. Skipping.")
                continue 

            problem_prompt = get_problem_description(problem_data, task_id)
            if problem_prompt is None:
                print(f"Warning: No problem description found for task_id '{task_id}'. Skipping.")
                continue

            print(f"Processing task {i+1}/{len(task_id_order)}: {task_id}")
            
            selected_code = call_llm_for_selection(args.model, api_key, problem_prompt, candidates_for_task)

            if selected_code is not None:
                output_item = {
                    "task_id": task_id,
                    "code": selected_code,
                    "entry_point": candidates_for_task[0].get('entry_point')
                }
                f_out.write(json.dumps(output_item) + '\n')
                f_out.flush() 
                print(f"Selected and wrote code for task {task_id}.")
            else:
                print(f"Could not get a valid selection for task {task_id}. Skipping and not writing.")
            
            time.sleep(1)

    print("Selection process complete.")

if __name__ == "__main__":
    main()