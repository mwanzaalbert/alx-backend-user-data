#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Filtered logger module."""

import os
import logging
import re
from typing import List, Tuple, Union, Any
from datetime import datetime
import mysql.connector
from mysql.connector.connection import MySQLConnection
from mysql.connector.connection import MySQLConnectionAbstract


# Define the fields that are considered PII
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """Replaces occurrences of fields in a msg with the redaction string."""
    # pylint: disable=unused-argument
    pattern = f"({'|'.join(fields)})=([^{separator}]+)"
    return re.sub(pattern, lambda m: f"{m.group(1)}={redaction}", message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initializes the RedactingFormatter with specified fields.

        Args:
            fields (List[str]): Fields to redact in log messages.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Applies redaction to sensitive fields in the log record message.

        Args:
            record (logging.LogRecord): The log record to format.

        Returns:
            str: The formatted log message with sensitive information redacted.
        """
        record.msg = filter_datum(
            self.fields, self.REDACTION, record.msg, self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)


def get_logger() -> logging.Logger:
    """Creates and returns a logger with specified settings."""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(fields=list(PII_FIELDS)))

    logger.addHandler(stream_handler)

    return logger


def get_db() -> Union[MySQLConnection, MySQLConnectionAbstract]:
    """
    Connects to the MySQL database using credentials from environment variables
    and returns the MySQLConnection object.

    Returns:
        MySQLConnection: The connection to the MySQL database.
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


def format_row(row: Tuple[str, ...], headers: List[str]) -> str:
    """
    Formats a database row into a log message string.

    Args:
        row (Tuple[str, ...]): A tuple representing a row of data from the
        database.
        headers (List[str]): A list of column headers corresponding to the row
        data.

    Returns:
        str: A formatted string where each field is 'header=value'.
    """
    return "; ".join(f"{header}={value}" for header, value in zip(headers,
                                                                  row))


def main() -> None:
    """
    Retrieve all rows from the users table and log each row with
    sensitive data filtered.
    """
    # Configure logging with RedactingFormatter
    logger = get_logger()

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users")

    # Get column names
    headers = [i[0] for i in cursor.description] if cursor.description else []
    rows = cursor.fetchall()
    for row in rows:
        #         message = format_row(row, headers)
        # Casting row elements to string
        message = format_row(
            tuple(str(value) if value is not None else "" for value in row),
            headers)

#         log_record = logging.LogRecord(
#             "user_data", logging.INFO, int, int, message, None, None
#         )
        log_record = logging.LogRecord(
            "user_data", logging.INFO, __file__, 0, message, None, None)
        logger.handle(log_record)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
