#!/usr/bin/env python3
import bcrypt

def hash_password(password: str) -> bytes:
    """
    Hashes a password with a randomly generated salt using bcrypt.
    
    Args:
        password (str): The password to hash.
        
    Returns:
        bytes: The salted, hashed password as a byte string.
    """
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates that the provided password matches the hashed password.
    
    Args:
        hashed_password (bytes): The previously hashed password.
        password (str): The plain-text password to verify.
        
    Returns:
        bool: True if the password is valid, False otherwise.
    """
    # Check if the password matches the hashed password
    return bcrypt.checkpw(password.encode(), hashed_password)


if __name__ == "__main__":
    password = "MyAmazingPassw0rd"
    print(hash_password(password))
    print(hash_password(password))
    
    encrypted_password = hash_password(password)
    print(encrypted_password)
    print(is_valid(encrypted_password, password))
