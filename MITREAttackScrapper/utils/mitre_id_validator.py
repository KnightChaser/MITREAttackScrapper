# MITREAttackScrapper/utils/mitre_id_validator.py
import re
from functools import wraps
from typing import Callable

def validate_mitre_technique_id(function: Callable) -> Callable:
    """
    A wrapper function to validate the MITRE ATT&CK technique ID. 
    
    The format of the MITRE ATT&CK technique ID is the following:

    .. code-block:: text

        TXXXX[.YYY]
        ||     |
        ||     +-> Optional sub-technique ID (2 digits)
        ||
        |+-> Technique ID (4 digits)
        |
        +-> Prefix "T' meaning "Technique"
        
    parameters
    ----------
    function : Callable
        The function to be wrapped.

    returns
    -------
    Callable
        The wrapped function that requires the MITRE ATT&CK technique ID with valid format
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

    The format of the MITRE ATT&CK tactic ID is the following:

    .. code-block:: text

        TAXXXX
        | |
        | +-> Tactic ID (4 digits)
        |
        +-> Prefix "TA" meaning "Tactic"
    
    parameters
    ----------
    function : Callable
        The function to be wrapped.

    returns
    -------
    Callable
        The wrapped function that requires the MITRE ATT&CK tactic ID with valid format
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

    The format of the MITRE ATT&CK mitigation ID is the following:

    .. code-block:: text

        MXXXX
        ||
        |+-> Mitigation ID (4 digits)
        |
        +-> Prefix "M" meaning "Mitigation"

    parameters
    ----------
    function : Callable
        The function to be wrapped.

    returns
    -------
    Callable
        The wrapped function that requires the MITRE ATT&CK mitigation ID with valid format
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
