import random

def scoring_strategy_similarity(samples):
    similarity_threshold = 0.97  
    groups = []

    for sample in samples:
        code_text = sample['code']
        code_text_processed = ''.join(code_text.split())

        placed = False
        for group in groups:
            group_code_text = group[0]['code']
            group_code_text_processed = ''.join(group_code_text.split())

            intersection = set(code_text_processed) & set(group_code_text_processed)
            union = set(code_text_processed) | set(group_code_text_processed)
            if union:
                similarity = len(intersection) / len(union)
            else:
                similarity = 0

            if similarity >= similarity_threshold:
                group.append(sample)
                placed = True
                break
        if not placed:
            groups.append([sample])

    max_group = max(groups, key=lambda g: len(g))
    selected_item = random.choice(max_group)
    selected_sample = selected_item
    return selected_sample