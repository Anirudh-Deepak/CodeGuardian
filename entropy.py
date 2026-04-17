import math

def calculate_entropy(text):
    if not text:
        return 0

    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = - sum([p * math.log2(p) for p in prob])

    return entropy


def is_high_entropy(value, threshold=4.5):
    return calculate_entropy(value) > threshold