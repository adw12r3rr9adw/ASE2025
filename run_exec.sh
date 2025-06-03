#!/bin/bash
MODE="experiment"             
MODEL="gemini"                     
DATASET="mbpp"                
BEGIN=972                     
END=975                   
MAX_STEP=200              
UNROLL=3                     

if [ "$MODE" == "experiment" ]; then
    if [ -n "$BEGIN" ] && [ -n "$END" ]; then
        python main_execution.py --mode "$MODE" --model "$MODEL" --dataset "$DATASET" \
                                 --begin "$BEGIN" --end "$END" \
                                 --max_step "$MAX_STEP" --unroll "$UNROLL" 
    else
        python main_execution.py --mode "$MODE" --model "$MODEL" --dataset "$DATASET" \
                                 --max_step "$MAX_STEP" --unroll "$UNROLL" 
    fi
else
    python main_execution.py --mode "$MODE" --model "$MODEL" --dataset "$DATASET" \
                             --max_step "$MAX_STEP" --unroll "$UNROLL" 
fi
