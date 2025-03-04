import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.regex.Pattern;

/**
 * Defend Your Code - Security Assignment
 * 
 * This program validates user inputs, securely processes data, and prevents common
 * security vulnerabilities including overflow, path traversal, and improper input.
 * 
 * Security Features:
 * - Input validation for names, integers, and filenames
 * - Path traversal prevention
 * - Integer overflow detection and prevention
 * - Secure password handling with salted SHA-256 hashing
 * - Error logging with protected access
 * - File permission controls
 * 
 * @author Team 5 - Binal Dhaliwal, Anagha Krishna, Bhavneet Bhargava
 * @version 1.0
 */
public class DefendCode {
    // Constants
    private static final int MAX_NAME = 50; // Maximum length for names
    // Regular expression pattern for valid name characters: letters (a-z, A-Z), hyphens (-), 
    //apostrophes ('), and whitespace characters (spaces, tabs, line breaks)
    private static final String NAME_STRING = "^[a-zA-Z\\-'\\s]+$"; 
    // File extension for text files
    private static final String TEXT_FILE_EXTENSION = ".txt";
    // File name for storing the hashed password (hidden from users)
    private static final String HIDDEN_PASSWORD_FILE = ".password.dat";
    // File name for logging errors (hidden from users)
    private static final String HIDDEN_ERROR_LOG_FILE = ".error_log.txt";
    // Compiled pattern for validating names based on the NAME_PATTERN_STRING regular expression
    private static final Pattern VALID_NAME = Pattern.compile(NAME_STRING);
    // Scanner object for reading user input from the keyboard
    private static final Scanner keyboardInput = new Scanner(System.in);
    
    
    /**
     * Main entry point for the program.
     * 
     * Prompts the user to enter their first and last name, two integer values, 
     * and the names of an input and output file. The input file is read and 
     * processed, and the results are written to the output file.
     * 
     * Password verification is handled by calling the handlePasswordVerification() 
     * method. If an error occurs during processing, an error message is written 
     * to the error log and printed to the console.
     */
    public static void main(String[] args) {
        // Main program logic
        try {
            // Prompt the user for input
            String userFirstName = promptForValidName("first");
            String userLastName = promptForValidName("last");
            
            // Prompt the user for integer input
            long theFirstInteger = promptForValidInteger("first");
            long theSecondInteger = promptForValidInteger("second");
            
            // Prompt the user for file names
            String theInputFileName = promptForValidFileName("input");
            String theOutputFileName = promptForValidFileName("output");
            
            // Ensure input and output files are different
            while (theInputFileName.equals(theOutputFileName)) {
                writeToErrorLog("Error: Input and output files must be different.");
                System.out.println("Error: Input and output files must be different.");
                theOutputFileName = promptForValidFileName("output");
            }
            
            // Ensure input and output files are not reserved
            while (theInputFileName.equals(HIDDEN_PASSWORD_FILE) || 
                   theOutputFileName.equals(HIDDEN_PASSWORD_FILE) ||
                   theInputFileName.equals(HIDDEN_ERROR_LOG_FILE) || 
                   theOutputFileName.equals(HIDDEN_ERROR_LOG_FILE)) {
                writeToErrorLog("Error: Cannot use reserved file names.");
                System.out.println("Error: Cannot use reserved file names.");
                if (theInputFileName.equals(HIDDEN_PASSWORD_FILE) || 
                    theInputFileName.equals(HIDDEN_ERROR_LOG_FILE)) {
                    theInputFileName = promptForValidFileName("input");
                } else {
                    theOutputFileName = promptForValidFileName("output");
                }
            }
            // Handle password verification
            handlePasswordVerification();
            // Process and write files
            processAndWriteFiles(userFirstName, userLastName, theFirstInteger, 
                            theSecondInteger, theInputFileName, theOutputFileName);
        } catch (Exception ex) {
            writeToErrorLog("Unexpected error in main process: " + ex.getMessage());
            System.out.println("An unexpected error occurred. Please check the error log for details.");
        } finally {
            // Close the keyboard scanner
            keyboardInput.close();
        }
    }
    
    /**
     * Prompts the user for a valid name (max MAX_NAME_LENGTH characters, only
     * letters, spaces, hyphens, and apostrophes allowed). If the user enters an
     * invalid name, an error message is printed and the loop continues until
     * the user enters a valid name.
     * 
     * @param theNameType the type of name being entered (e.g. "first", "last")
     * @return the validated name
     */
    private static String promptForValidName(String theNameType) {
        while (true) {
            System.out.println("\nPlease enter your " + theNameType + " name (max " + MAX_NAME + 
                                 " characters, only letters, spaces, hyphens, and apostrophes allowed):");
            String userInput = keyboardInput.nextLine().trim();
            if (userInput.isEmpty()) {
                String err = "Name cannot be empty for " + theNameType + " name.";
                System.out.println("Error: " + err);
                writeToErrorLog(err);
                continue;
            }
            if (userInput.length() > MAX_NAME) {
                String err = "Name exceeds maximum length of " + MAX_NAME + " characters for " + theNameType + " name.";
                System.out.println("Error: " + err);
                writeToErrorLog(err);
                continue;
            }
            if (!VALID_NAME.matcher(userInput).matches()) {
                String err = "Name contains invalid characters for " + theNameType + " name: " + userInput;
                System.out.println("Error: " + err);
                writeToErrorLog(err);
                continue;
            }
            return userInput;
        }
    }
    
    
    
    /**
     * Prompts the user for a valid integer (range: -2,147,483,648 to 2,147,483,647).
     * If the user enters an invalid integer, an error message is printed and
     * the loop continues until the user enters a valid integer.
     * 
     * @param thePosition the position of the integer (e.g. "first", "second")
     * @return the validated integer
     */
    private static long promptForValidInteger(String thePosition) {
        while (true) {
            System.out.println("\nPlease enter the " + thePosition + " integer value (range: -2,147,483,648 to 2,147,483,647):");
            String userInput = keyboardInput.nextLine().trim();
            if (userInput.isEmpty()) {
                String err = "Integer value cannot be empty for " + thePosition + " integer.";
                System.out.println("Error: " + err);
                writeToErrorLog(err);
                continue;
            }
            try {
                return Integer.parseInt(userInput);
            } catch (NumberFormatException ex) {
                String err = "Invalid integer format for " + thePosition + " integer: " + userInput;
                System.out.println("Error: " + err);
                writeToErrorLog(err);
            }
        }
    }
    
    
    
    /**
     * Prompts the user for a valid file name (must end with TEXT_FILE_EXTENSION
     * and be in the current directory). If the user enters an invalid file name,
     * an error message is printed and the loop continues until the user enters a
     * valid file name.
     * 
     * @param theFileType the type of file being entered (e.g. "input", "output")
     * @return the validated file name
     */
    private static String promptForValidFileName(String theFileType) {
        while (true) {
            System.out.println("\nPlease enter the " + theFileType + " file name (must end with " + TEXT_FILE_EXTENSION + 
                                 " and be in the current directory):");
            String fileName = keyboardInput.nextLine().trim();
            if (fileName.isEmpty()) {
                String err = "File name cannot be empty for " + theFileType + " file.";
                System.out.println("Error: " + err);
                writeToErrorLog(err);
                continue;
            }
            File fileObject = new File(fileName);
            // Check for path traversal attempts
            if (!fileObject.getName().equals(fileName)) {
                String err = "Path traversal attempt detected for " + theFileType + " file: " + fileName;
                System.out.println("Error: Path traversal is not allowed. Please provide only a file name.");
                writeToErrorLog(err);
                continue;
            }
            // *** Reserved File Names Check ***
            if (fileName.equals(HIDDEN_PASSWORD_FILE) || fileName.equals(HIDDEN_ERROR_LOG_FILE)) {
                String err = "Error: Cannot use reserved file names: " + fileName;
                System.out.println(err);
                writeToErrorLog(err);
                continue;
            }
            if (!fileName.endsWith(TEXT_FILE_EXTENSION)) {
                String err = "File must have " + TEXT_FILE_EXTENSION + " extension: " + fileName;
                System.out.println("Error: " + err);
                writeToErrorLog(err);
                continue;
            }
            if (theFileType.equals("input") && !Files.exists(Paths.get(fileName))) {
                String err = "Input file does not exist: " + fileName;
                System.out.println("Error: " + err);
                writeToErrorLog(err);
                continue;
            }
            return fileName;
        }
    }
    
    /**
     * Handles password verification and creation. If the password file does not
     * exist or is invalid, creates a new password. If the password is correct,
     * prints a success message. If the password is incorrect, prints an error
     * message and attempts to verify up to MAX_PASSWORD_ATTEMPTS times. If the
     * maximum attempts are reached, prints a message indicating too many failed
     * attempts and creates a new password. If an exception occurs during
     * password verification, prints an error message and creates a new password.
     */
    private static void handlePasswordVerification() {
        // Read the password hash and salt from the password file
        String storedPasswordHash = null;
        // byte[] storedPasswordSalt = null;
        byte[] storedPasswordSalt = null;
        // byte[] storedPasswordSalt = null;
        try {
            if (Files.exists(Paths.get(HIDDEN_PASSWORD_FILE))) {
                String[] passwordFileData = new String(Files.readAllBytes(Paths.get(HIDDEN_PASSWORD_FILE))).split(":");
                if (passwordFileData.length == 2) {
                    storedPasswordHash = passwordFileData[0];
                    storedPasswordSalt = Base64.getDecoder().decode(passwordFileData[1]);
                }
            }
            // If the password file does not exist or is invalid, create a new password
            if (storedPasswordHash == null || storedPasswordSalt == null) {
                createNewPassword();
                return;
            }
            // Verify the password
            boolean isPasswordCorrect = false;
            int failedAttempts = 0;
            final int MAX_PASSWORD_ATTEMPTS = 3;
            while (!isPasswordCorrect && failedAttempts < MAX_PASSWORD_ATTEMPTS) {
                System.out.println("\nPlease enter your password to continue:");
                String enteredPassword = getPasswordFromUser();
                
                String hashedEnteredPassword = hashThePassword(enteredPassword, storedPasswordSalt);
                
                if (hashedEnteredPassword.equals(storedPasswordHash)) {
                    isPasswordCorrect = true;
                    System.out.println("Password verified successfully.");
                } else {
                    failedAttempts++;
                    System.out.println("Incorrect password. Attempts remaining: " + (MAX_PASSWORD_ATTEMPTS - failedAttempts));
                    writeToErrorLog("Incorrect password. Attempts remaining: " + (MAX_PASSWORD_ATTEMPTS - failedAttempts));
                }
            }
            // If the maximum attempts are reached, create a new password
            if (!isPasswordCorrect) {
                String errorMessage = "Too many failed password attempts. Creating a new password.";
                writeToErrorLog(errorMessage);
                System.out.println("Too many failed attempts. Creating a new password.");
                createNewPassword();
            }
            
        } catch (Exception ex) {
            writeToErrorLog("Error in password verification: " + ex.getMessage());
            System.out.println("An error occurred during password verification. Creating a new password.");
            createNewPassword();
        }
    }
    
    
 
    /**
     * Prompts the user to create a new password and saves it to the password file.
     * 
     * The user is prompted to enter a new password and confirm it. The password must
     * meet the requirements of having at least 8 characters, one uppercase letter, one
     * lowercase letter, one digit, and one special character. If the password does not
     * meet the requirements, the user is prompted to try again. If the passwords do not
     * match, the user is prompted to try again. Once a valid password is entered,
     * a salt is generated and the password is hashed using SHA-256. The hashed password
     * and salt are then written to the password file. The file is set to be readable and
     * writable only by the current user.
     * 
     * If an error occurs during the process, an error message is written to the error
     * log and the user is prompted to try again.
     */
    private static void createNewPassword() {
        // Prompt the user to create a new password
        boolean isPasswordSet = false;

        while (!isPasswordSet) {
            System.out.println("\nCreate a new password (minimum 8 characters, must include at least one uppercase letter, " +
                             "one lowercase letter, one digit, and one special character):");
            String newPassword = getPasswordFromUser();
            // Check if the password meets the requirements
            if (!isPasswordValid(newPassword)) {
                writeToErrorLog("Password does not meet requirements. Please try again.");
                System.out.println("Password does not meet requirements. Please try again.");
                continue;
            }
            // Prompt the user to confirm the password
            System.out.println("Confirm your password:");
            String confirmPassword = getPasswordFromUser();
            // Check if the passwords match
            if (!newPassword.equals(confirmPassword)) {
                writeToErrorLog("Passwords do not match. Please try again.");
                System.out.println("Passwords do not match. Please try again.");
                continue;
            }
            // Hash the password
            try {
                SecureRandom randomGenerator = new SecureRandom();
                byte[] passwordSalt = new byte[16];
                randomGenerator.nextBytes(passwordSalt);
                
                String hashedPassword = hashThePassword(newPassword, passwordSalt);
                
                String saltAsString = Base64.getEncoder().encodeToString(passwordSalt);
                Files.write(Paths.get(HIDDEN_PASSWORD_FILE), (hashedPassword + ":" + saltAsString).getBytes(),
                         StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                // Set file permissions
                try {
                    File passwordFile = new File(HIDDEN_PASSWORD_FILE);
                    passwordFile.setReadable(false, false);
                    passwordFile.setReadable(true, true);
                    passwordFile.setWritable(false, false);
                    passwordFile.setWritable(true, true);
                } catch (Exception ex) {
                    writeToErrorLog("Could not set file permissions: " + ex.getMessage());
                }
                // Password set successfully
                isPasswordSet = true;
                System.out.println("Password created and saved successfully.");
            } catch (Exception ex) {
                writeToErrorLog("Error creating password: " + ex.getMessage());
                System.out.println("An error occurred while saving the password. Please try again.");
            }
        }
    }
    

    /**
     * Gets a password from the user without echoing the input. If the program
     * is run from an IDE, it falls back to reading a line of text from the
     * standard input. The password is then converted to a string and the
     * character array is cleared for security reasons.
     *
     * @return the password entered by the user
     */
    private static String getPasswordFromUser() {
        // Get password from user
        Console consoleInput = System.console();
        // If the program is run from an IDE, fall back to reading a line of text from the standard input
        if (consoleInput != null) {
            char[] passwordChars = consoleInput.readPassword();
            String enteredPassword = new String(passwordChars);
            Arrays.fill(passwordChars, ' ');  
            return enteredPassword;
        } else {
            // If the program is run from the command line, read a line of text from the standard input
            return keyboardInput.nextLine();
        }
    }
    
    /**
     * Checks if a password is valid. A valid password is one that is at least
     * 8 characters long and contains at least one uppercase letter, one
     * lowercase letter, one digit, and one special character.
     * 
     * @param thePassword the password to check
     * @return true if the password is valid, false otherwise
     */
    private static boolean isPasswordValid(String thePassword) {
        // Check if the password is at least 8 characters long
        if (thePassword.length() < 8) {
            return false;
        }
        // Check if the password contains at least one uppercase letter, one lowercase letter, one digit, and one special character
        boolean hasUppercase = false;
        // Check if the password contains at least one uppercase letter
        boolean hasLowercase = false;
        // Check if the password contains at least one lowercase letter
        boolean hasDigit = false;
        // Check if the password contains at least one digit
        boolean hasSpecial = false;
        // Check if the password contains at least one special character
        for (char currentChar : thePassword.toCharArray()) {
            // Check if the current character is an uppercase letter
            if (Character.isUpperCase(currentChar)) {
                hasUppercase = true;
                // Check if the current character is a lowercase letter
            } else if (Character.isLowerCase(currentChar)) {
                hasLowercase = true;
                // Check if the current character is a digit
            } else if (Character.isDigit(currentChar)) {
                hasDigit = true;
                // Check if the current character is a special character
            } else {
                hasSpecial = true;
            }
        }
        // Return true if the password is valid
        return hasUppercase && hasLowercase && hasDigit && hasSpecial;
    }
    

    /**
     * Hashes a password using SHA-256 with a salt.
     * 
     * @param thePassword the password to hash
     * @param theSalt the salt to use when hashing the password
     * @return the hashed password as a Base64-encoded string
     * @throws NoSuchAlgorithmException if SHA-256 is not available
     */
    private static String hashThePassword(String thePassword, byte[] theSalt) throws NoSuchAlgorithmException {
        // Hash the password
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        // Update the message digest with the salt
        messageDigest.update(theSalt);
        // Update the message digest with the password
        byte[] hashedPasswordBytes = messageDigest.digest(thePassword.getBytes(StandardCharsets.UTF_8));
        // Return the hashed password as a Base64-encoded string
        return Base64.getEncoder().encodeToString(hashedPasswordBytes);
    }
    
    
    /**
     * Processes two integer values and writes user information, calculations, and 
     * input file contents to an output file. This method performs integer overflow 
     * checks and logs errors if any issues occur during file processing.
     * 
     * @param theFirstName the first name of the user
     * @param theLastName the last name of the user
     * @param theFirstInt the first integer value for calculations
     * @param theSecondInt the second integer value for calculations
     * @param theInputFileName the name of the input file to read from
     * @param theOutputFileName the name of the output file to write to
     */
    private static void processAndWriteFiles(String theFirstName, String theLastName, long theFirstInt, 
                                         long theSecondInt, String theInputFileName, String theOutputFileName) {
        // Perform integer overflow checks
        try {
            // Convert the integer values to BigIntegers
            BigInteger firstBigInt = BigInteger.valueOf(theFirstInt);
            BigInteger secondBigInt = BigInteger.valueOf(theSecondInt);
            BigInteger sumResult = firstBigInt.add(secondBigInt);
            BigInteger productResult = firstBigInt.multiply(secondBigInt);
            // Perform integer overflow checks
            checkNumberForOverflow(sumResult, "Sum");
            checkNumberForOverflow(productResult, "Product");
            // Read the contents of the input file
            String inputFileContent = new String(Files.readAllBytes(Paths.get(theInputFileName)));
            // Write user information, calculations, and input file contents to the output file
            try (PrintWriter fileWriter = new PrintWriter(new FileWriter(theOutputFileName))) {
                fileWriter.println("USER INFORMATION:");
                fileWriter.println("First Name: " + theFirstName);
                fileWriter.println("Last Name: " + theLastName);
                fileWriter.println("\nINTEGER VALUES:");
                fileWriter.println("First Integer: " + theFirstInt);
                fileWriter.println("Second Integer: " + theSecondInt);
                fileWriter.println("\nCALCULATIONS:");
                fileWriter.println("Sum: " + sumResult);
                fileWriter.println("Product: " + productResult);
                fileWriter.println("\nINPUT FILE:");
                fileWriter.println("File Name: " + theInputFileName);
                fileWriter.println("\nINPUT FILE CONTENTS:");
                fileWriter.println(inputFileContent);
                // Close the file writer
                System.out.println("\nProcessing complete. Data has been written to " + theOutputFileName);
            }
            // Log any errors
        } catch (Exception ex) {
            writeToErrorLog("Error processing files: " + ex.getMessage());
            System.out.println("An error occurred while processing the files. Please check the error log for details.");
        }
    }
    
    
    /**
     * Checks if the provided BigInteger value exceeds the range of a 32-bit integer.
     * Logs an error message if an overflow would occur and prints a warning.
     * 
     * @param theValue the BigInteger value to check for overflow
     * @param theOperation the name of the operation being performed, used in error messages
     */
    private static void checkNumberForOverflow(BigInteger theValue, String theOperation) {
        // Define the range of a 32-bit integer
        BigInteger minIntValue = BigInteger.valueOf(Integer.MIN_VALUE);
        BigInteger maxIntValue = BigInteger.valueOf(Integer.MAX_VALUE);
        // Check if the value exceeds the range
        if (theValue.compareTo(minIntValue) < 0 || theValue.compareTo(maxIntValue) > 0) {
            // Log the error
            String errorMessage = theOperation + " would cause overflow! Value: " + theValue;
            // Write the error to the error log
            writeToErrorLog(errorMessage);
            // Print a warning
            System.out.println("Warning: " + errorMessage);
            System.out.println("The calculation will continue using a larger data type.");
        }
    }
    
    
    /**
     * Writes an error message to the hidden error log file.
     * 
     * The file is created if it does not already exist, and the file permissions are set so that only the current user can read and write to the file.
     * The error message is written to the file with the current timestamp and a newline separator.
     * 
     * @param theErrorMessage the error message to write to the log file
     */
    private static void writeToErrorLog(String theErrorMessage) {
        // Write the error message to the hidden error log file
        try {
            // Create the error log file if it does not already exist
            if (!Files.exists(Paths.get(HIDDEN_ERROR_LOG_FILE))) {
                Files.createFile(Paths.get(HIDDEN_ERROR_LOG_FILE));
                // Set the file permissions
                File logFile = new File(HIDDEN_ERROR_LOG_FILE);
                logFile.setReadable(false, false);
                logFile.setReadable(true, true);
                logFile.setWritable(false, false);
                logFile.setWritable(true, true);
            }
            // Write the error message to the file
            try (FileWriter fileWriter = new FileWriter(HIDDEN_ERROR_LOG_FILE, true);
                 BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                 PrintWriter printWriter = new PrintWriter(bufferedWriter)) {
                printWriter.println(java.time.LocalDateTime.now() + ": " + theErrorMessage);
            }
            // Log any errors
        } catch (Exception ex) {
            System.err.println("Failed to log error: " + ex.getMessage());
        }
    }
}