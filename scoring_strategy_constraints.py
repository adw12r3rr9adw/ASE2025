import os
import pickle
import random
import logging
import multiprocessing
from functools import lru_cache, cmp_to_key, partial
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Dict, Tuple, Set, Optional, Any
import claripy

logger = logging.getLogger(__name__)
logger.propagate = True
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def normalize_constraint(constraint: claripy.ast.Bool) -> claripy.ast.Bool:
    if not isinstance(constraint, claripy.ast.Bool):
        return constraint
        
    symbols = []
    seen = set()
    
    for node in constraint.recursive_children_asts:
        if isinstance(node, claripy.ast.BV) and node.op == 'BVS':
            if node not in seen:
                symbols.append(node)
                seen.add(node)
    
    replace_map = {}
    for i, sym in enumerate(sorted(symbols, key=lambda s: str(s.args[0])), 1):
        new_name = f'var{i}'
        replace_map[sym] = claripy.BVS(new_name, sym.size(), explicit_name=True)
    
    new_cons = constraint
    for old, new in replace_map.items():
        new_cons = new_cons.replace(old, new)
    return claripy.simplify(new_cons)

def parse_constraints_from_pkl(file_path: str) -> List[Dict]:
    try:
        with open(file_path, 'rb') as f:
            return pickle.load(f)
    except Exception as e:
        logger.warning(f"Failed to load constraints {file_path}: {str(e)}")
        return []


def is_subset_with_solver(
    set_a: List[claripy.ast.Bool], 
    set_b: List[claripy.ast.Bool],
    solver: claripy.Solver
) -> bool:
    if not set_a:
        return True

    solver.add(claripy.And(*set_a))
    solver.add(claripy.Not(claripy.And(*set_b)))

    return not solver.satisfiable()

def compare_single_path(
    path1: Dict, 
    path2: Dict,
    sample1_id: str,
    sample2_id: str,
    path_num: int
) -> Optional[Dict]:
    try:
        cons1 = path1['constraints']
        cons2 = path2['constraints']
        
        # Use cached normalization
        normalized_cons1 = [normalize_constraint(c) for c in cons1]
        normalized_cons2 = [normalize_constraint(c) for c in cons2]
        
        # Check bi-directional subset/superset
        is_subset = is_subset_with_solver(normalized_cons1, normalized_cons2, claripy.Solver())
        is_superset = is_subset_with_solver(normalized_cons2, normalized_cons1, claripy.Solver())
        
        if is_subset and not is_superset:
            return {
                "sample1": sample1_id,
                "sample2": sample2_id,
                "path_num": path_num,
                "relation": "subset"
            }
        elif is_superset and not is_subset:
            return {
                "sample1": sample1_id,
                "sample2": sample2_id,
                "path_num": path_num,
                "relation": "superset"
            }
        return None
    except Exception as e:
        logger.error(f"Error comparing path {path_num}: {str(e)}")
        return None

def compare_sample_pair(pair: Tuple[Dict, Dict]) -> List[Dict]:
    sample1, sample2 = pair
    min_paths = min(
        len(sample1['constraints']['paths']),
        len(sample2['constraints']['paths'])
    )
    
    relations = []
    
    for idx in range(min_paths):
        path1 = sample1['constraints']['paths'][idx]
        path2 = sample2['constraints']['paths'][idx]
        
        result = compare_single_path(
            path1, path2,
            sample1['unique_id'], sample2['unique_id'],
            idx + 1
        )
        if result:
            return result 
    
    return None

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

def parallel_load_samples(samples: List[Dict], res_dir: str) -> List[Dict]:
    processed_samples = []
    with ProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
        future_to_sample = {
            executor.submit(load_sample_constraints, sample, res_dir): sample
            for sample in samples
        }
        
        for future in as_completed(future_to_sample):
            try:
                result = future.result()
                if result:
                    processed_samples.append(result)
            except Exception as e:
                logger.error(f"Error loading sample constraints: {str(e)}")
    
    return processed_samples

def parallel_compare_samples(samples: List[Dict]) -> List[Dict]:
    sample_pairs = [
        (samples[i], samples[j]) 
        for i in range(len(samples)) 
        for j in range(i + 1, len(samples))
    ]
    
    relationships = []
    total_pairs = len(sample_pairs)
    
    compare_func = partial(compare_sample_pair)
    
    with ProcessPoolExecutor(max_workers=4) as executor:
        future_to_pair = {
            executor.submit(compare_func, pair): pair
            for pair in sample_pairs
        }
        
        for future in as_completed(future_to_pair):
            try:
                relations = future.result()
                if relations:
                    relationships.append(relations)
            except Exception as e:
                logger.error(f"Error comparing sample pair: {str(e)}")
    
    return relationships

def apply_partial_ordering(
    samples: List[Dict], 
    relations: List[Dict]
) -> List[Dict]:
    partial_order = {sample['unique_id']: set() for sample in samples}
    for relation in relations:
        if relation['relation'] == 'subset':
            partial_order[relation['sample1']].add(relation['sample2'])
        elif relation['relation'] == 'superset':
            partial_order[relation['sample2']].add(relation['sample1'])
    
    def compare_samples(s1: Dict, s2: Dict) -> int:
        uid1, uid2 = s1['unique_id'], s2['unique_id']
        
        if uid2 in partial_order[uid1]:
            return -1
        if uid1 in partial_order[uid2]:
            return 1
            
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
        raise ValueError("Sample list cannot be empty")
        
    processed_samples = parallel_load_samples(samples, res_dir)
    
    if not processed_samples:
        return random.choice(samples)
    
    relations = parallel_compare_samples(processed_samples)
    ordered_samples = apply_partial_ordering(processed_samples, relations)
    
    if debug_mode:
        logger.debug("Sorting result:")
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
        logger.error(f"Scoring strategy failed: {str(e)}")
