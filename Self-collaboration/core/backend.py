import openai
from openai import OpenAI
import time
import os

MODEL_API_KEYS = {
}


def call_chatgpt(prompt, model='gpt-4o-mini-2024-07-18', stop=None, temperature=0., top_p=1.0,
        max_tokens=128, echo=False, majority_at=None):
    
    client = OpenAI(
        base_url="",
        api_key=MODEL_API_KEYS.get(model, "api-key-not-found"),
        timeout=120
    )
    num_completions = majority_at if majority_at is not None else 1
    num_completions_batch_size = 10

    completions = []
    for i in range(20 * (num_completions // num_completions_batch_size + 1)):
        try:
            requested_completions = min(num_completions_batch_size, num_completions - len(completions))

            response = client.chat.completions.create(
            model=model,
            messages=prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            n=requested_completions
            )
            
            completions.extend([choice.message.content for choice in response.choices])
            if len(completions) >= num_completions:
                return completions[:num_completions]
        except Exception as e:
            print(f"Unexpected error: {e}")
            time.sleep(5)
    raise RuntimeError('Failed to call GPT API')