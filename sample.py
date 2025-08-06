import re
import logging

# Configure logging
logging.basicConfig(filename='input_validation.log', level=logging.WARNING)

try:
    user_input = input("Enter a number: ")

    # Length-based DoS mitigation
    if len(user_input) > 5:
        raise ValueError("Input too long")

    # Regex to validate integer only
    if not re.fullmatch(r"\d{1,5}", user_input):
        raise ValueError("Invalid input format")

    number = int(user_input)
    print(number)

except ValueError as ve:
    logging.warning(f"ValueError: {ve}")
    print(f"Invalid input: {ve}")

except KeyboardInterrupt:
    logging.warning("KeyboardInterrupt: User terminated input")
    print("Input canceled by user.")

except EOFError:
    logging.warning("EOFError: Unexpected EOF from input")
    print("No input received.")

