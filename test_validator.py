from utils.validator import TargetValidator

targets = [
    "127.0.0.1",
    "scanme.nmap.org",
    "google.com",
    "!!!!!!",
    "abc@@@",
    ""
]

for target in targets:
    print(target, "->", TargetValidator.validate(target))
