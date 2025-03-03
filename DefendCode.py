import os
import re
import base64
import hashlib
import time
from getpass import getpass


MAX_NAME_LENGTH = 50
NAME_PATTERN_STRING = r"^[a-zA-Z\-'\s]+$"
TEXT_FILE_EXTENSION = ".txt"
HIDDEN_PASSWORD_FILE = ".password.dat"
HIDDEN_ERROR_LOG_FILE = ".error_log.txt"
VALID_NAME_PATTERN = re.compile(NAME_PATTERN_STRING)


def main():
    try:
        user_first_name = prompt_for_valid_name("first")
        user_last_name = prompt_for_valid_name("last")

        the_first_integer = prompt_for_valid_integer("first")
        the_second_integer = prompt_for_valid_integer("second")

        the_input_file_name = prompt_for_valid_file_name("input")
        the_output_file_name = prompt_for_valid_file_name("output")

        while the_input_file_name == the_output_file_name:
            print("Error: Input and output files must be different.")
            the_output_file_name = prompt_for_valid_file_name("output")

        while the_input_file_name in [HIDDEN_PASSWORD_FILE, HIDDEN_ERROR_LOG_FILE] or \
                the_output_file_name in [HIDDEN_PASSWORD_FILE, HIDDEN_ERROR_LOG_FILE]:
            print("Error: Cannot use reserved file names.")
            if the_input_file_name in [HIDDEN_PASSWORD_FILE, HIDDEN_ERROR_LOG_FILE]:
                the_input_file_name = prompt_for_valid_file_name("input")
            else:
                the_output_file_name = prompt_for_valid_file_name("output")

        handle_password_verification()

        process_and_write_files(user_first_name, user_last_name, the_first_integer,
                                the_second_integer, the_input_file_name, the_output_file_name)

    except Exception as ex:
        write_to_error_log(f"Unexpected error in main process: {str(ex)}")
        print("An unexpected error occurred. Please check the error log for details.")


def prompt_for_valid_name(name_type):
    while True:
        user_input = input(f"\nPlease enter your {name_type} name (max {MAX_NAME_LENGTH} "
                           "characters, only letters, spaces, hyphens, and apostrophes allowed): ").strip()

        if not user_input:
            print("Error: Name cannot be empty. Please try again.")
            continue

        if len(user_input) > MAX_NAME_LENGTH:
            print(f"Error: Name exceeds maximum length of {MAX_NAME_LENGTH} characters. Please try again.")
            continue

        if not VALID_NAME_PATTERN.match(user_input):
            print("Error: Name contains invalid characters. Only letters, spaces, hyphens, and apostrophes are allowed.")
            continue

        return user_input


def prompt_for_valid_integer(position):
    while True:
        user_input = input(f"\nPlease enter the {position} integer value (range: -2,147,483,648 to 2,147,483,647): ").strip()

        if not user_input:
            print("Error: Input cannot be empty. Please try again.")
            continue

        try:
            return int(user_input)
        except ValueError:
            print("Error: Invalid integer format. Please enter a valid number within the specified range.")


def prompt_for_valid_file_name(file_type):
    while True:
        file_name = input(f"\nPlease enter the {file_type} file name (must end with {TEXT_FILE_EXTENSION} "
                          "and be in the current directory): ").strip()

        if not file_name:
            print("Error: File name cannot be empty. Please try again.")
            continue

        if os.path.isabs(file_name) or '..' in file_name.split(os.sep):
            print("Error: Path traversal is not allowed. Please provide only a file name.")
            continue

        if not file_name.endswith(TEXT_FILE_EXTENSION):
            print(f"Error: File must have {TEXT_FILE_EXTENSION} extension. Please try again.")
            continue

        if file_type == "input" and not os.path.exists(file_name):
            print("Error: Input file does not exist. Please try again.")
            continue

        return file_name


def handle_password_verification():
    stored_password_hash = None
    stored_password_salt = None

    try:
        if os.path.exists(HIDDEN_PASSWORD_FILE):
            with open(HIDDEN_PASSWORD_FILE, 'r') as f:
                password_file_data = f.read().split(":")
                if len(password_file_data) == 2:
                    stored_password_hash = password_file_data[0]
                    stored_password_salt = base64.b64decode(password_file_data[1])

        if stored_password_hash is None or stored_password_salt is None:
            create_new_password()
            return

        is_password_correct = False
        failed_attempts = 0
        MAX_PASSWORD_ATTEMPTS = 3

        while not is_password_correct and failed_attempts < MAX_PASSWORD_ATTEMPTS:
            entered_password = get_password_from_user()
            hashed_entered_password = hash_the_password(entered_password, stored_password_salt)

            if hashed_entered_password == stored_password_hash:
                is_password_correct = True
                print("Password verified successfully.")
            else:
                failed_attempts += 1
                print(f"Incorrect password. Attempts remaining: {MAX_PASSWORD_ATTEMPTS - failed_attempts}")

        if not is_password_correct:
            print("Too many failed attempts. Creating a new password.")
            create_new_password()

    except Exception as ex:
        write_to_error_log(f"Error in password verification: {str(ex)}")
        print("An error occurred during password verification. Creating a new password.")
        create_new_password()


def create_new_password():
    is_password_set = False

    while not is_password_set:
        new_password = get_password_from_user(
            prompt="Create a new password (minimum 8 characters, must include at least one uppercase letter, "
                   "one lowercase letter, one digit, and one special character):"
        )

        if not is_password_valid(new_password):
            print("Password does not meet requirements. Please try again.")
            continue

        confirm_password = get_password_from_user(prompt="Confirm your password: ")

        if new_password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue

        try:
            password_salt = os.urandom(16)
            hashed_password = hash_the_password(new_password, password_salt)

            salt_as_string = base64.b64encode(password_salt).decode()
            with open(HIDDEN_PASSWORD_FILE, 'w') as f:
                f.write(f"{hashed_password}:{salt_as_string}")

            os.chmod(HIDDEN_PASSWORD_FILE, 0o600)

            is_password_set = True
            print("Password created and saved successfully.")

        except Exception as ex:
            write_to_error_log(f"Error creating password: {str(ex)}")
            print("An error occurred while saving the password. Please try again.")


def get_password_from_user(prompt="Please enter your password: "):
    return getpass(prompt)



def is_password_valid(password):
    if len(password) < 8:
        return False

    has_uppercase = any(c.isupper() for c in password)
    has_lowercase = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    return has_uppercase and has_lowercase and has_digit and has_special


def hash_the_password(password, salt):
    sha256 = hashlib.sha256()
    sha256.update(salt)
    sha256.update(password.encode('utf-8'))
    return base64.b64encode(sha256.digest()).decode()


def process_and_write_files(first_name, last_name, first_int, second_int, input_file_name, output_file_name):
    try:
        first_big_int = first_int
        second_big_int = second_int
        sum_result = first_big_int + second_big_int
        product_result = first_big_int * second_big_int

        check_number_for_overflow(sum_result, "Sum")
        check_number_for_overflow(product_result, "Product")

        with open(input_file_name, 'r') as file:
            input_file_content = file.read()

        with open(output_file_name, 'w') as file_writer:
            file_writer.write(f"USER INFORMATION:\nFirst Name: {first_name}\nLast Name: {last_name}\n\n")
            file_writer.write(f"INTEGER VALUES:\nFirst Integer: {first_int}\nSecond Integer: {second_int}\n\n")
            file_writer.write(f"CALCULATIONS:\nSum: {sum_result}\nProduct: {product_result}\n\n")
            file_writer.write(f"INPUT FILE:\nFile Name: {input_file_name}\n\nINPUT FILE CONTENTS:\n{input_file_content}")

        print(f"\nProcessing complete. Data has been written to {output_file_name}")

    except Exception as ex:
        write_to_error_log(f"Error processing files: {str(ex)}")
        print("An error occurred while processing the files. Please check the error log for details.")


def check_number_for_overflow(value, operation):
    min_int_value = -2147483648
    max_int_value = 2147483647

    if value < min_int_value or value > max_int_value:
        error_message = f"{operation} would cause overflow! Value: {value}"
        write_to_error_log(error_message)
        print(f"Warning: {error_message}")
        print("The calculation will continue using a larger data type.")


def write_to_error_log(error_message):
    try:
        if not os.path.exists(HIDDEN_ERROR_LOG_FILE):
            with open(HIDDEN_ERROR_LOG_FILE, 'w'):
                pass

        with open(HIDDEN_ERROR_LOG_FILE, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}: {error_message}\n")

    except Exception as ex:
        print(f"Failed to log error: {str(ex)}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram was interrupted. Exiting gracefully...")

   # main()
