import re
from functools import wraps
from typing import Callable

def validate_mitre_technique_id(function: Callable) -> Callable:
    """
    A wrapper function to validate the MITRE ATT&CK technique ID.
    
    The format of the MITRE ATT&CK technique ID is as follows:

    .. code-block:: text

        TXXXX[.YYY]
        ||     |
        ||     +-> Optional sub-technique ID (3 digits)
        ||
        |+-> Technique ID (4 digits)
        |
        +-> Prefix "T" meaning "Technique"
        
    :param function: The function to be wrapped.
    :type function: Callable
    :return: The wrapped function that requires the MITRE ATT&CK technique ID with valid format.
    :rtype: Callable
    :raises ValueError: If the MITRE ATT&CK technique ID is not in the valid format.
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        pattern = r"^T\d{4}(\.\d{3})?$"
        # Iterate through all arguments and keyword arguments
        for arg in args:
            if isinstance(arg, str) and not re.match(pattern, arg):
                raise ValueError("Invalid MITRE ATT&CK technique ID, should be in the format of TXXXX[.YYY]")
        
        for key, value in kwargs.items():
            if isinstance(key, str) and key.endswith("technique_id"):
                if not re.match(pattern, value):
                    raise ValueError("Invalid MITRE ATT&CK technique ID, should be in the format of TXXXX[.YYY]")
        
        return function(*args, **kwargs)
    
    return wrapper

def validate_mitre_tactic_id(function: Callable) -> Callable:
    """
    A wrapper function to validate the MITRE ATT&CK tactic ID.

    The format of the MITRE ATT&CK tactic ID is as follows:

    .. code-block:: text

        TAXXXX
        | |
        | +-> Tactic ID (4 digits)
        |
        +-> Prefix "TA" meaning "Tactic"
    
    :param function: The function to be wrapped.
    :type function: Callable
    :return: The wrapped function that requires the MITRE ATT&CK tactic ID with valid format.
    :rtype: Callable
    :raises ValueError: If the MITRE ATT&CK tactic ID is not in the valid format.
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        pattern = r"^TA\d{4}$"
        # Iterate through all arguments and keyword arguments
        for arg in args:
            if isinstance(arg, str) and not re.match(pattern, arg):
                raise ValueError("Invalid MITRE ATT&CK tactic ID, should be in the format of TAXXXX")
        
        for key, value in kwargs.items():
            if isinstance(key, str) and key.endswith("tactic_id"):
                if not re.match(pattern, value):
                    raise ValueError("Invalid MITRE ATT&CK tactic ID, should be in the format of TAXXXX")
        
        return function(*args, **kwargs)
    
    return wrapper

def validate_mitre_mitigation_id(function: Callable) -> Callable:
    """
    A wrapper function to validate the MITRE ATT&CK mitigation ID.

    The format of the MITRE ATT&CK mitigation ID is as follows:

    .. code-block:: text

        MXXXX
        ||
        |+-> Mitigation ID (4 digits)
        |
        +-> Prefix "M" meaning "Mitigation"

    :param function: The function to be wrapped.
    :type function: Callable
    :return: The wrapped function that requires the MITRE ATT&CK mitigation ID with valid format.
    :rtype: Callable
    :raises ValueError: If the MITRE ATT&CK mitigation ID is not in the valid format.
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        pattern = r"^M\d{4}$"
        # Iterate through all arguments and keyword arguments
        for arg in args:
            if isinstance(arg, str) and not re.match(pattern, arg):
                raise ValueError("Invalid MITRE ATT&CK mitigation ID, should be in the format of MXXXX")
        
        for key, value in kwargs.items():
            if isinstance(key, str) and key.endswith("mitigation_id"):
                if not re.match(pattern, value):
                    raise ValueError("Invalid MITRE ATT&CK mitigation ID, should be in the format of MXXXX")
        
        return function(*args, **kwargs)
    
    return wrapper

def validate_mitre_group_id(function: Callable) -> Callable:
    """
    A wrapper function to validate the MITRE ATT&CK group ID.

    The format of the MITRE ATT&CK group ID is as follows:

    .. code-block:: text

        GXXXX
        ||
        |+-> Group ID (4 digits)
        |
        +-> Prefix "G" meaning "Group"

    :param function: The function to be wrapped.
    :type function: Callable
    :return: The wrapped function that requires the MITRE ATT&CK group ID with valid format.
    :rtype: Callable
    :raises ValueError: If the MITRE ATT&CK group ID is not in the valid format.
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        pattern = r"^G\d{4}$"
        # Iterate through all arguments and keyword arguments
        for arg in args:
            if isinstance(arg, str) and not re.match(pattern, arg):
                raise ValueError("Invalid MITRE ATT&CK group ID, should be in the format of GXXXX")
        
        for key, value in kwargs.items():
            if isinstance(key, str) and key.endswith("group_id"):
                if not re.match(pattern, value):
                    raise ValueError("Invalid MITRE ATT&CK group ID, should be in the format of GXXXX")
        
        return function(*args, **kwargs)
    
    return wrapper

def validate_mitre_software_id(function: Callable) -> Callable:
    """
    A wrapper function to validate the MITRE ATT&CK software ID.

    The format of the MITRE ATT&CK software ID is as follows:

    .. code-block:: text

        SXXXX
        ||
        |+-> Software ID (4 digits)
        |
        +-> Prefix "S" meaning "Software"

    :param function: The function to be wrapped.
    :type function: Callable
    :return: The wrapped function that requires the MITRE ATT&CK software ID with valid format.
    :rtype: Callable
    :raises ValueError: If the MITRE ATT&CK software ID is not in the valid format.
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        pattern = r"^S\d{4}$"
        # Iterate through all arguments and keyword arguments
        for arg in args:
            if isinstance(arg, str) and not re.match(pattern, arg):
                raise ValueError("Invalid MITRE ATT&CK software ID, should be in the format of SXXXX")
        
        for key, value in kwargs.items():
            if isinstance(key, str) and key.endswith("software_id"):
                if not re.match(pattern, value):
                    raise ValueError("Invalid MITRE ATT&CK software ID, should be in the format of SXXXX")
        
        return function(*args, **kwargs)
    
    return wrapper