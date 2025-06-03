import os
import pickle
import random
import logging
from functools import cmp_to_key
from typing import List, Dict, Optional
import claripy

logger = logging.getLogger(__name__)
logger.propagate = True
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def parse_constraints_from_pkl(file_path: str) -> List[Dict]:
    try:
        with open(file_path, 'rb') as f:
            return pickle.load(f)
    except Exception as e:
        logger.warning(f"Failed to load constraints from {file_path}: {str(e)}")
        return []

def load_sample_constraints(sample: Dict, res_dir: str) -> Optional[Dict]:
    constraints_file = os.path.join(res_dir, f"{sample['unique_id']}.pkl")
    if not os.path.exists(constraints_file):
        return None

    constraints = parse_constraints_from_pkl(constraints_file)
    if not constraints:
        return None

    sample['constraints'] = {
        'path_count': len(constraints),
        'paths': [{
            'constraints': path['constraints'],
            'constraint_count': len(path['constraints'])
        } for path in constraints]
    }
    return sample

def load_samples(samples: List[Dict], res_dir: str) -> List[Dict]:
    processed_samples = []
    for sample in samples:
        try:
            result = load_sample_constraints(sample, res_dir)
            if result:
                processed_samples.append(result)
        except Exception as e:
            logger.error(f"Error while loading constraints for sample: {str(e)}")
    return processed_samples

def apply_path_based_sorting(samples: List[Dict]) -> List[Dict]:
    def compare_samples(s1: Dict, s2: Dict) -> int:
        path_diff = s2['constraints']['path_count'] - s1['constraints']['path_count']
        if path_diff != 0:
            return path_diff
        
        max_cons1 = max(p['constraint_count'] for p in s1['constraints']['paths'])
        max_cons2 = max(p['constraint_count'] for p in s2['constraints']['paths'])
        return max_cons2 - max_cons1

    return sorted(samples, key=cmp_to_key(compare_samples))


def scoring_strategy_constraints(
    samples: List[Dict], 
    res_dir: str, 
    debug_mode: bool = False
) -> Dict:
    if not samples:
        raise ValueError("Sample list cannot be empty.")

    processed_samples = load_samples(samples, res_dir)
    
    if not processed_samples:
        return random.choice(samples)

    ordered_samples = apply_path_based_sorting(processed_samples)

    if debug_mode:
        logger.debug("Sorted samples:")
        for i, sample in enumerate(ordered_samples[:10], 1):
            logger.debug(f"{i}. {sample['unique_id']} (path count: {sample['constraints']['path_count']})")

    return ordered_samples[0] if ordered_samples else random.choice(samples)

if __name__ == "__main__":
    samples = [{'unique_id': f'sample_{i}'} for i in range(10)]
    res_dir = './constraints'

    try:
        best_sample = scoring_strategy_constraints(samples, res_dir, debug_mode=True)
        logger.info(f"Best sample: {best_sample['unique_id']}")
    except Exception as e:
        logger.error(f"Constraint-based scoring failed: {str(e)}")
