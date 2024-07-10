# MITREAttackScrapper/utils/mitre_id_validator.py
import re
from functools import wraps
from typing import Callable

def validate_mitre_technique_id(function: Callable) -> Callable:
    """
    A wrapper function to validate the MITRE ATT&CK technique ID.
    It generally follows the format as the following:
    ```text
          "."(dot) if it is a sub-technique
          |
          |  3 digits of sub-technique ID
          |  |
    TXXXX[.YYY]
    |   |
    |   4 digits of main technique ID
    |
    "T" prefix meaning "Technique"
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        pattern = r"^T\d{4}(\.\d{3})?$"
        # Iterate through all arguments and keyword arguments
        for arg in args:
            if isinstance(arg, str) and not re.match(pattern, arg):
                raise ValueError("Invalid MITRE ATT&CK technique ID, should be in the format of TXXXX[.YYY]")
        
        for key, value in kwargs.items():
            if isinstance(key, str) and key.endswith("_technique_id"):
                if not re.match(pattern, value):
                    raise ValueError("Invalid MITRE ATT&CK technique ID, should be in the format of TXXXX[.YYY]")
        
        return function(*args, **kwargs)
    
    return wrapper

def validate_mitre_tactic_id(function: Callable) -> Callable:
    """
    A wrapper function to validate the MITRE ATT&CK tactic ID.
    It generally follows the format as the following:
    ```text
    TAXXXX
    | |
    | 4 digits of tactic ID
    |
    "TA" prefix meaning "Tactic"
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        pattern = r"^TA\d{4}$"
        # Iterate through all arguments and keyword arguments
        for arg in args:
            if isinstance(arg, str) and not re.match(pattern, arg):
                raise ValueError("Invalid MITRE ATT&CK tactic ID, should be in the format of TAXXXX")
        
        for key, value in kwargs.items():
            if isinstance(key, str) and key.endswith("_tactic_id"):
                if not re.match(pattern, value):
                    raise ValueError("Invalid MITRE ATT&CK tactic ID, should be in the format of TAXXXX")
        
        return function(*args, **kwargs)
    
    return wrapper

def validate_mitre_mitigation_id(function: Callable) -> Callable:
    """
    A wrapper function to validate the MITRE ATT&CK mitigation ID.
    It generally follows the format as the following:
    ```text
    MXXXX
    ||
    |4 digits of mitigation ID
    |
    "M" prefix meaning "Mitigation"
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        pattern = r"^M\d{4}$"
        # Iterate through all arguments and keyword arguments
        for arg in args:
            if isinstance(arg, str) and not re.match(pattern, arg):
                raise ValueError("Invalid MITRE ATT&CK mitigation ID, should be in the format of MXXXX")
        
        for key, value in kwargs.items():
            if isinstance(key, str) and key.endswith("_mitigation_id"):
                if not re.match(pattern, value):
                    raise ValueError("Invalid MITRE ATT&CK mitigation ID, should be in the format of MXXXX")
        
        return function(*args, **kwargs)
    
    return wrapper
