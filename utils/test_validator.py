from utils.validator import TargetValidator
from utils.logger import logger

targets = [
    "127.0.0.1",
    "scanme.nmap.org",
    "google.com",
    "!!!!!!",
    "abc@@@",
    ""
]

for target in targets:
    logger.info(f"{target} -> {TargetValidator.validate(target)}")