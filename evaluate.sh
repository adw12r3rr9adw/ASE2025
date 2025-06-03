#!/bin/bash

DATASET="humaneval" 
MODEL="ds"    
STRATEGY="constraints"
FLAG="ablation"


selected_file="data/${DATASET}/${MODEL}/selected_codes_${DATASET}_${MODEL}_${STRATEGY}_${FLAG}.jsonl"
  
if [[ ! -f "$selected_file" ]]; then
    echo "Error: Selected file not found: $selected_file"
    exit 1
fi

problem_file="data/${DATASET}.jsonl"
if [[ ! -f "$problem_file" ]]; then
    echo "Error: Problem file not found: $problem_file"
    exit 1
fi


python evaluation/evaluate_functional_correctness.py "$selected_file" --problem_file "$problem_file"