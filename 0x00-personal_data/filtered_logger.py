#!/usr/bin/env python3

"""
Filtered logger module
"""

import os
import logging
import re
from typing import List, Tuple
from datetime import datetime
import mysql.connector
from mysql.connector.connection import MySQLConnection


# Define the fields that are considered PII
PII_FIELDS = ("name", "email", "phone", "ssn", "password")

def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    pattern = f"({'|'.join(fields)})=([^;]+)"
    return re.sub(pattern, lambda m: f"{m.group(1)}={redaction}", message)

class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        record.msg = filter_datum(self.fields, self.REDACTION, record.msg, self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)

def get_logger() -> logging.Logger:
    """Creates and returns a logger with specified settings."""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(fields=PII_FIELDS))
    
    logger.addHandler(stream_handler)
    
    return logger


def get_db() -> MySQLConnection:
    """
    Connects to the MySQL database using credentials from environment variables
    and returns the MySQLConnection object.
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    database = os.getenv("PERSONAL_DATA_DB_NAME")

    return mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=database
    )

def format_row(row: Tuple[str], headers: List[str]) -> str:
    """
    Formats a database row into a log message string.
    """
    return "; ".join(f"{header}={value}" for header, value in zip(headers, row))


def main():
    """
    Main function to retrieve all rows from the users table and log each row with
    sensitive data filtered.
    """
    # Configure logging with RedactingFormatter
    logger = get_logger()

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users")

    headers = [i[0] for i in cursor.description]  # Get column names
    for row in cursor:
        message = format_row(row, headers)
        log_record = logging.LogRecord(
            "user_data", logging.INFO, None, None, message, None, None
        )
        logger.handle(log_record)

    cursor.close()
    db.close()

if __name__ == "__main__":
    main()
#     fields = ["password", "date_of_birth"]
#     messages = ["name=egg;email=eggmin@eggsample.com;password=eggcellent;date_of_birth=12/12/1986;",
#                 "name=bob;email=bob@dylan.com;password=bobbycool;date_of_birth=03/04/1993;"]
# 
#     for message in messages:
#         print(filter_datum(fields, 'xxx', message, ';'))
#     print()
#     
#     message = "name=Bob;email=bob@dylan.com;ssn=000-123-0000;password=bobby2019;"
#     log_record = logging.LogRecord("my_logger", logging.INFO, None, None, message, None, None)
#     formatter = RedactingFormatter(fields=("email", "ssn", "password"))
#     print(formatter.format(log_record))
#     
#     print()
#     
#     print(get_logger.__annotations__.get('return'))
#     print("PII_FIELDS: {}".format(len(PII_FIELDS)))
#     
#     print()
#     db = get_db()
#     cursor = db.cursor()
#     cursor.execute("SELECT COUNT(*) FROM users;")
#     for row in cursor:
#         print(row[0])
#     cursor.close()
#     db.close()
