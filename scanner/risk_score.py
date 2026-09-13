WEIGHTS = {"critical": 40, "high": 25, "medium": 15, "low": 5, "info": 0}


def calculate_score(findings):
    raw = sum(WEIGHTS.get(f.get("severity", "info"), 0) for f in findings)
    score = min(raw, 100)
    if score >= 70:
        level = "Critical"
    elif score >= 45:
        level = "High"
    elif score >= 20:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "Good"
    return score, level
