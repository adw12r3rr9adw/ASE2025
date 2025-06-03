#!/bin/bash


dataset="humaneval" 
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

dataset_path="USC/evaluation/${dataset}.jsonl"
input_path="USC/${dataset}/${model_short}/merged_${model_short}.jsonl"
output_path="USC/${dataset}/${model_short}/${model_short}_USC.jsonl"

python main.py \
  --dataset "$dataset" \
  --model "$model" \
  --input_path "$input_path" \
  --output_path "$output_path" \
  --lang cpp \

cd USC/evaluation
python evaluate_functional_correctness.py "$output_path" --problem_file "./${dataset}.jsonl"
