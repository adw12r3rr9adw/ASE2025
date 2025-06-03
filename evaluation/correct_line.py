import json

def replace_task_ids(file1_path, file2_path, output_path):
    with open(file1_path, 'r', encoding='utf-8') as f1, open(file2_path, 'r', encoding='utf-8') as f2:
        lines1 = [json.loads(line) for line in f1]
        lines2 = [json.loads(line) for line in f2]

    assert len(lines1) == len(lines2), "Files must have the same number of lines"

    for i in range(len(lines1)):
        lines1[i]["task_id"] = lines2[i].get("task_id", lines1[i].get("task_id"))

    with open(output_path, 'w', encoding='utf-8') as out:
        for item in lines1:
            out.write(json.dumps(item, ensure_ascii=False) + '\n')

replace_task_ids("", "", "")
