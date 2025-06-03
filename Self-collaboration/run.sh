#!/bin/bash

dataset="mbpp"  
model_short="gemini"



if [ "$model_short" == "ds" ]; then
  model="deepseek-v3"
elif [ "$model_short" == "gemini" ]; then
  model="gemini-2.0-flash-thinking-exp-01-21"
elif [ "$model_short" == "4o" ]; then
  model="gpt-4o"
elif [ "$model_short" == "4omini" ]; then
  model="gpt-4o-mini"
else
  echo "Unknown model short name: $model_short"
  exit 1
fi

input_path="Self-collaboration-Code-Generation-mbpp/data/${dataset}/${model_short}/${model_short}_tested_random_526.jsonl"
output_path="Self-collaboration-Code-Generation-mbpp/data/${dataset}/${model_short}/${model_short}_tested_random_526_output.jsonl"

python main.py \
  --dataset "$dataset" \
  --signature \
  --model "$model" \
  --max_round 5 \
  --input_path "$input_path" \
  --output_path "$output_path" \
  --append \
  --lang cpp \
  --start_id 0 \
  --end_id 1000

cd /data/Self-collaboration-Code-Generation-mbpp/evaluation
pwd
echo ${output_path}
echo ${dataset}
python correct_line.py \
  --file1 "$output_path" \
  --file2 "${dataset}.jsonl" \
  --output "$output_path"
python evaluate_functional_correctness.py "$output_path" --problem_file "./${dataset}.jsonl"
