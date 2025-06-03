strategy="ldb"
dataset="humaneval"
model="gemini-2.0-flash-thinking-exp-01-21"
dataset_path="LLMDebugger-main/input_data/humaneval/seed/gemini/gemini_seed.jsonl"

dataset_filename=$(basename "$dataset_path" .jsonl)

run_name="${dataset_filename}_${model}"

python main.py \
  --model $model \
  --dataset $dataset \
  --run_name "$run_name" \
  --root_dir ../output_data/$strategy/$dataset/$run_name \
  --dataset_path  $dataset_path \
  --strategy $strategy \
  --seedfile /LLMDebugger-main/input_data/humaneval/seed/gemini/gemini_seed.jsonl \
  --pass_at_k "1" \
  --max_iters "5" \
  --n_proc "1" \
  --port "8000" \
  --testfile ../input_data/$dataset/test/tests.jsonl \
  --verbose