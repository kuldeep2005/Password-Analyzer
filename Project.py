import re
import math

# Common passwords list (you can expand this later)
common_passwords = [
    "123456", "password", "123456789", "qwerty", "abc123",
    "111111", "123123", "admin", "welcome", "letmein"
]


def check_password_rules(password):
    rules = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"[0-9]", password)),
        "special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    }
    return rules


def calculate_entropy(password):
    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        charset += 32

    entropy = len(password) * math.log2(charset) if charset else 0
    return round(entropy, 2)


def check_common_password(password):
    return password.lower() in common_passwords


def estimate_crack_time(entropy):
    guesses_per_second = 1e9  # attacker speed
    seconds = (2 ** entropy) / guesses_per_second

    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} days"
    else:
        return f"{seconds/31536000:.2f} years"


def password_strength_score(rules):
    score = sum(rules.values())

    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Moderate"
    else:
        return "Strong"


def give_suggestions(rules):
    suggestions = []

    if not rules["length"]:
        suggestions.append("Use at least 8-12 characters.")
    if not rules["uppercase"]:
        suggestions.append("Add uppercase letters.")
    if not rules["lowercase"]:
        suggestions.append("Add lowercase letters.")
    if not rules["digit"]:
        suggestions.append("Include numbers.")
    if not rules["special"]:
        suggestions.append("Include special characters (!@#$ etc).")

    return suggestions


def analyze_password(password):
    print("\n----- Password Security Report -----")

    rules = check_password_rules(password)
    entropy = calculate_entropy(password)
    strength = password_strength_score(rules)
    crack_time = estimate_crack_time(entropy)

    for rule, passed in rules.items():
        print(f"{rule.capitalize()} check:", "OK" if passed else "Missing")

    if check_common_password(password):
        print("WARNING: This password is very common!")

    print("\nEntropy:", entropy, "bits")
    print("Strength:", strength)
    print("Estimated crack time:", crack_time)

    suggestions = give_suggestions(rules)

    if suggestions:
        print("\nSuggestions to improve password:")
        for s in suggestions:
            print("-", s)
    else:
        print("\nGood password! No improvements needed.")


# Run program
password = input("Enter a password to analyze: ")
analyze_password(password)
