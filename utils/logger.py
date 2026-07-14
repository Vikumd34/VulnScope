import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, 'vulnscope.log')

def get_logger(name='vulnscope'):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(LOG_PATH, maxBytes=5*1024*1024, backupCount=3)
    fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    # also log to console for dev
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    logger.addHandler(console)
    logger.propagate = False
    return logger

logger = get_logger()
