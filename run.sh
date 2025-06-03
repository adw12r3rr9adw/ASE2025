#!/bin/bash


DEBUG_LIST="MBCPP/107"  
DATASET="mbpp"
MODEL="4o" 
STRATEGY="constraints"  
OUTPUT_DIR="output"  
FLAG="top7"


python3 main.py \
    --debug_list "$DEBUG_LIST" \
    --dataset "$DATASET" \
    --model "$MODEL" \
    --strategy "$STRATEGY" \
    --output_dir "$OUTPUT_DIR"\
    --flag "$FLAG" \
    --top_n 7

cd evaluation
printf "Evaluating functional correctness...\n"
python evaluate_functional_correctness.py ../data/${DATASET}/${MODEL}/selected_codes_${DATASET}_${MODEL}_${STRATEGY}_${FLAG}.jsonl --problem_file ../data/${DATASET}.jsonl