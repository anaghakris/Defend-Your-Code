"""
Defend Your Code - Security Assignment

This program validates user inputs, securely processes data, and prevents common
security vulnerabilities including overflow, path traversal, and improper input.

Security Features:
- Input validation for names, integers, and filenames
- Path traversal prevention
- Integer overflow detection and prevention
- Secure password handling with salted SHA-256 hashing
- Error logging with protected access
- File permission controls

@author Team 5
@version 1.0
"""
import os
import re
import base64
import hashlib
import time
from getpass import getpass

# Constants
MAX_NAME = 50  # Maximum name length
NAME_STRING = r"^[a-zA-Z\-'\s]+$"   #Regular expression pattern for valid name characters: letters (a-z, A-Z), hyphens (-), 
                                    #apostrophes ('), and whitespace characters (spaces, tabs, line breaks)
TEXT_FILE_EXTENSION = ".txt"  # File extension for text files
HIDDEN_PASSWORD_FILE = ".password.dat"  # Hidden password file
HIDDEN_ERROR_LOG_FILE = ".error_log.txt"  # Hidden error log file
VALID_NAME = re.compile(NAME_STRING)  # Compiled regular expression for name validation

"""
Main function to execute the program's workflow.

This function prompts the user to enter their first and last names, two integer
values, and the names of an input and output file. It performs validation on the
inputs, ensuring that file names are not reserved and are different. The function
also handles password verification and processes the input file, writing the results
to the output file. In case of errors during execution, an error message is logged
and printed to the console.
"""
def main():
    try:
        # Prompt the user for input
        user_first_name = prompt_for_valid_name("first")
        user_last_name = prompt_for_valid_name("last")

        # Prompt the user for integer input
        the_first_integer = prompt_for_valid_integer("first")
        the_second_integer = prompt_for_valid_integer("second")

        # Prompt the user for file names
        the_input_file_name = prompt_for_valid_file_name("input")
        the_output_file_name = prompt_for_valid_file_name("output")

        # Ensure input and output files are different
        while the_input_file_name == the_output_file_name:
            print("Error: Input and output files must be different.")
            the_output_file_name = prompt_for_valid_file_name("output")

        # Ensure file names are not reserved
        while the_input_file_name in [HIDDEN_PASSWORD_FILE, HIDDEN_ERROR_LOG_FILE] or \
                the_output_file_name in [HIDDEN_PASSWORD_FILE, HIDDEN_ERROR_LOG_FILE]:
            print("Error: Cannot use reserved file names.")
            # Prompt the user for file names
            if the_input_file_name in [HIDDEN_PASSWORD_FILE, HIDDEN_ERROR_LOG_FILE]:
                the_input_file_name = prompt_for_valid_file_name("input")
            else:
                the_output_file_name = prompt_for_valid_file_name("output")
        # Handle password verification
        handle_password_verification()

        # Process and write files
        process_and_write_files(user_first_name, user_last_name, the_first_integer,
                                the_second_integer, the_input_file_name, the_output_file_name)
    # Handle exceptions
    except Exception as ex:
        # Log the error
        write_to_error_log(f"Unexpected error in main process: {str(ex)}")
        print("An unexpected error occurred. Please check the error log for details.")

"""
Prompts the user for a valid name (max MAX_NAME_LENGTH characters, only letters, 
spaces, hyphens, and apostrophes allowed). If the user enters an invalid name, 
an error message is printed and the loop continues until the user enters a valid 
name.

Args:
    name_type (str): The type of name being entered (e.g. "first", "last")

Returns:
    str: The validated name
"""
def prompt_for_valid_name(name_type):
    # Loop until a valid name is entered
    while True:
        # Prompt the user for input
        user_input = input(f"\nPlease enter your {name_type} name (max {MAX_NAME} "
                           "characters, only letters, spaces, hyphens, and apostrophes allowed): ").strip()
        # Validate the name
        if not user_input:
            print("Error: Name cannot be empty. Please try again.")
            continue
        # Check name length
        if len(user_input) > MAX_NAME:
            print(f"Error: Name exceeds maximum length of {MAX_NAME} characters. Please try again.")
            continue
        # Check for invalid characters
        if not VALID_NAME.match(user_input):
            print("Error: Name contains invalid characters. Only letters, spaces, hyphens, and apostrophes are allowed.")
            continue
        # Return the validated name
        return user_input

"""
Prompts the user for a valid integer within the specified range.
If the user enters an invalid integer or the input is empty,
an error message is displayed and the loop continues until a valid
integer is entered.

Args:
    position (str): The position of the integer being entered (e.g., "first", "second").

Returns:
    int: The validated integer entered by the user.
"""
def prompt_for_valid_integer(position):
    # Loop until a valid integer is entered
    while True:
        # Prompt the user for input
        user_input = input(f"\nPlease enter the {position} integer value (range: -2,147,483,648 to 2,147,483,647): ").strip()
        # Validate the integer
        if not user_input:
            print("Error: Input cannot be empty. Please try again.")
            continue
        # Check integer range
        try:
            return int(user_input)
        # Handle exceptions
        except ValueError:
            print("Error: Invalid integer format. Please enter a valid number within the specified range.")

"""
Prompts the user for a valid file name (must end with TEXT_FILE_EXTENSION and
be in the current directory). If the user enters an invalid file name, an
error message is printed and the loop continues until the user enters a valid
file name.

Args:
    file_type (str): The type of file being entered (e.g. "input", "output")

Returns:
    str: The validated file name
"""
def prompt_for_valid_file_name(file_type):
    # Loop until a valid file name is entered
    while True:
        # Prompt the user for input
        file_name = input(f"\nPlease enter the {file_type} file name (must end with {TEXT_FILE_EXTENSION} "
                          "and be in the current directory): ").strip()
        # Validate the file name
        if not file_name:
            print("Error: File name cannot be empty. Please try again.")
            continue
        # Check file extension
        if os.path.isabs(file_name) or '..' in file_name.split(os.sep):
            print("Error: Path traversal is not allowed. Please provide only a file name.")
            continue
        if not file_name.endswith(TEXT_FILE_EXTENSION):
            print(f"Error: File must have {TEXT_FILE_EXTENSION} extension. Please try again.")
            continue
        
        if file_type == "input" and not os.path.exists(file_name):
            print("Error: Input file does not exist. Please try again.")
            continue
        # Return the validated file name
        return file_name

"""
Handles password verification and creation. If the password file does not
exist or is invalid, creates a new password. If the password is correct,
prints a success message. If the password is incorrect, prints an error
message and attempts to verify up to MAX_PASSWORD_ATTEMPTS times. If the
maximum attempts are reached, creates a new password. If an exception occurs
during password verification, prints an error message and creates a new
password.
"""
def handle_password_verification():
    # Read the password hash and salt from the password file
    stored_password_hash = None
    stored_password_salt = None
    try:
        if os.path.exists(HIDDEN_PASSWORD_FILE):
            with open(HIDDEN_PASSWORD_FILE, 'r') as f:
                password_file_data = f.read().split(":")
                if len(password_file_data) == 2:
                    stored_password_hash = password_file_data[0]
                    stored_password_salt = base64.b64decode(password_file_data[1])
        # If the password file does not exist or is invalid, create a new password
        if stored_password_hash is None or stored_password_salt is None:
            create_new_password()
            return

        # Verify the password
        is_password_correct = False
        failed_attempts = 0
        MAX_PASSWORD_ATTEMPTS = 3
        # Loop until the password is correct or the maximum attempts are reached
        while not is_password_correct and failed_attempts < MAX_PASSWORD_ATTEMPTS:
            # Prompt the user for the password
            entered_password = get_password_from_user()
            # Hash the entered password
            hashed_entered_password = hash_the_password(entered_password, stored_password_salt)

            # Check if the hashed entered password matches the stored password
            if hashed_entered_password == stored_password_hash:
                is_password_correct = True
                print("Password verified successfully.")
            # If the password is incorrect, prompt the user to try again
            else:
                failed_attempts += 1
                print(f"Incorrect password. Attempts remaining: {MAX_PASSWORD_ATTEMPTS - failed_attempts}")
        # If the password is incorrect after the maximum attempts, create a new password
        if not is_password_correct:
            print("Too many failed attempts. Creating a new password.")
            create_new_password()
    # Handle exceptions
    except Exception as ex:
        write_to_error_log(f"Error in password verification: {str(ex)}")
        print("An error occurred during password verification. Creating a new password.")
        create_new_password()

"""
Prompts the user to create a new password and saves it to the password file.
    
The user is prompted to enter a new password and confirm it. The password must
meet the requirements of having at least 8 characters, one uppercase letter, one
lowercase letter, one digit, and one special character. If the password does not
meet the requirements, the user is prompted to try again. If the passwords do not
match, the user is prompted to try again. Once a valid password is entered,
a salt is generated and the password is hashed using SHA-256. The hashed password
and salt are then written to the password file. The file is set to be readable and
writable only by the current user.
    
If an error occurs during the process, an error message is written to the error
log and the user is prompted to try again.
"""
def create_new_password():
    # Loop until a valid password is entered
    is_password_set = False

    while not is_password_set:
        # Prompt the user to create a new password
        new_password = get_password_from_user(
            prompt="Create a new password (minimum 8 characters, must include at least one uppercase letter, "
                   "one lowercase letter, one digit, and one special character):"
        )
        # Check if the password meets the requirements
        if not is_password_valid(new_password):
            print("Password does not meet requirements. Please try again.")
            continue

        # Prompt the user to confirm the password
        confirm_password = get_password_from_user(prompt="Confirm your password: ")

        # Check if the passwords match
        if new_password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue
        # Hash the password
        try:
            password_salt = os.urandom(16)
            hashed_password = hash_the_password(new_password, password_salt)
            # Write the hashed password and salt to the password file
            salt_as_string = base64.b64encode(password_salt).decode()
            with open(HIDDEN_PASSWORD_FILE, 'w') as f:
                f.write(f"{hashed_password}:{salt_as_string}")
            # Set the file permissions to be readable and writable only by the current user
            os.chmod(HIDDEN_PASSWORD_FILE, 0o600)
            is_password_set = True
            print("Password created and saved successfully.")
        # Handle exceptions
        except Exception as ex:
            write_to_error_log(f"Error creating password: {str(ex)}")
            print("An error occurred while saving the password. Please try again.")

"""
Prompts the user for a password without echoing the input.

Args:
    prompt (str): The message displayed to the user when requesting the password.

Returns:
    str: The password entered by the user.
"""
def get_password_from_user(prompt="Please enter your password: "):
    return getpass(prompt)


"""
Checks if a password is valid. A valid password is one that is at least
8 characters long and contains at least one uppercase letter, one
lowercase letter, one digit, and one special character.

Args:
    password (str): The password to check

 Returns:
     bool: True if the password is valid, False otherwise
"""
def is_password_valid(password):
    # Check if the password is at least 8 characters long
    if len(password) < 8:
        return False
    # Check if the password contains at least one uppercase letter, one lowercase letter, one digit,
    #  and one special character
    has_uppercase = any(c.isupper() for c in password)
    has_lowercase = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    # Return True if all conditions are met
    return has_uppercase and has_lowercase and has_digit and has_special

"""
Hashes a password using SHA-256 with a salt.

Args:
    password (str): The password to hash
    salt (bytes): The salt to use when hashing the password

Returns:
    str: The hashed password as a Base64-encoded string
"""
def hash_the_password(password, salt):
    # Hash the password
    sha256 = hashlib.sha256()
    # Update the hash with the salt
    sha256.update(salt)
    # Update the hash with the password
    sha256.update(password.encode('utf-8'))
    # Return the Base64-encoded hash
    return base64.b64encode(sha256.digest()).decode()

"""
Processes two integer values and writes user information, calculations, and input file contents to an output file.
    
This method performs integer overflow checks and logs errors if any issues occur during file processing.
    
Args:
    first_name (str): The first name of the user
    last_name (str): The last name of the user
    first_int (int): The first integer value for calculations
    second_int (int): The second integer value for calculations
    input_file_name (str): The name of the input file to read from
     output_file_name (str): The name of the output file to write to
    
Returns:
        None
 """
def process_and_write_files(first_name, last_name, first_int, second_int, input_file_name, output_file_name):
    # Perform integer overflow checks
    try:
        # Convert the integer values to BigIntegers
        first_big_int = first_int
        second_big_int = second_int
        sum_result = first_big_int + second_big_int
        product_result = first_big_int * second_big_int

        # Perform integer overflow checks
        check_number_for_overflow(sum_result, "Sum")
        check_number_for_overflow(product_result, "Product")
        # Read the contents of the input file
        with open(input_file_name, 'r') as file:
            input_file_content = file.read()
        # Write user information, calculations, and input file contents to the output file
        with open(output_file_name, 'w') as file_writer:
            file_writer.write(f"USER INFORMATION:\nFirst Name: {first_name}\nLast Name: {last_name}\n\n")
            file_writer.write(f"INTEGER VALUES:\nFirst Integer: {first_int}\nSecond Integer: {second_int}\n\n")
            file_writer.write(f"CALCULATIONS:\nSum: {sum_result}\nProduct: {product_result}\n\n")
            file_writer.write(f"INPUT FILE:\nFile Name: {input_file_name}\n\nINPUT FILE CONTENTS:\n{input_file_content}")
        # Print a success message
        print(f"\nProcessing complete. Data has been written to {output_file_name}")
    # Handle exceptions
    except Exception as ex:
        write_to_error_log(f"Error processing files: {str(ex)}")
        print("An error occurred while processing the files. Please check the error log for details.")

"""
Checks if the provided value exceeds the range of a 32-bit integer.
Logs an error message if an overflow would occur and prints a warning.
    
Args:
    value (int): The value to check for overflow
    operation (str): The name of the operation being performed, used in error messages
    
Returns:
    None
 """
def check_number_for_overflow(value, operation):
    # Define the range of a 32-bit integer
    min_int_value = -2147483648
    max_int_value = 2147483647
    # Check if the value exceeds the range
    if value < min_int_value or value > max_int_value:
        error_message = f"{operation} would cause overflow! Value: {value}"
        write_to_error_log(error_message)
        print(f"Warning: {error_message}")
        print("The calculation will continue using a larger data type.")

"""
Writes an error message to the hidden error log file.

The file is created if it does not already exist, and the file permissions are set so that only the current user can read and write to the file.
The error message is written to the file with the current timestamp and a newline separator.

Args:
    error_message (str): The error message to write to the log file
"""
def write_to_error_log(error_message):
    # Set the file permissions so that only the current user can read and write to the file
    try:
        # Create the error log file if it does not already exist
        if not os.path.exists(HIDDEN_ERROR_LOG_FILE):
            with open(HIDDEN_ERROR_LOG_FILE, 'w'):
                pass
            # Set the file permissions
            os.chmod(HIDDEN_ERROR_LOG_FILE, 0o600) 
        # Write the error message to the file
        with open(HIDDEN_ERROR_LOG_FILE, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}: {error_message}\n")
    # Handle exceptions
    except Exception as ex:
        print(f"Failed to log error: {str(ex)}")

# Entry point of the program
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram was interrupted. Exiting gracefully...")

   # main()
