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

public class DefendCode {
    private static final int MAX_NAME_LENGTH = 50;
    private static final String NAME_PATTERN_STRING = "^[a-zA-Z\\-'\\s]+$";
    private static final String TEXT_FILE_EXTENSION = ".txt";
    private static final String HIDDEN_PASSWORD_FILE = ".password.dat";
    private static final String HIDDEN_ERROR_LOG_FILE = ".error_log.txt";
    private static final Pattern VALID_NAME_PATTERN = Pattern.compile(NAME_PATTERN_STRING);
    private static final Scanner keyboardInput = new Scanner(System.in);
    
    public static void main(String[] args) {
        try {
            String userFirstName = promptForValidName("first");
            String userLastName = promptForValidName("last");
            
            long theFirstInteger = promptForValidInteger("first");
            long theSecondInteger = promptForValidInteger("second");
            
            String theInputFileName = promptForValidFileName("input");
            String theOutputFileName = promptForValidFileName("output");
            
            while (theInputFileName.equals(theOutputFileName)) {
                System.out.println("Error: Input and output files must be different.");
                theOutputFileName = promptForValidFileName("output");
            }
            
            while (theInputFileName.equals(HIDDEN_PASSWORD_FILE) || 
                   theOutputFileName.equals(HIDDEN_PASSWORD_FILE) ||
                   theInputFileName.equals(HIDDEN_ERROR_LOG_FILE) || 
                   theOutputFileName.equals(HIDDEN_ERROR_LOG_FILE)) {
                System.out.println("Error: Cannot use reserved file names.");
                if (theInputFileName.equals(HIDDEN_PASSWORD_FILE) || 
                    theInputFileName.equals(HIDDEN_ERROR_LOG_FILE)) {
                    theInputFileName = promptForValidFileName("input");
                } else {
                    theOutputFileName = promptForValidFileName("output");
                }
            }
            
            handlePasswordVerification();
            
            processAndWriteFiles(userFirstName, userLastName, theFirstInteger, 
                            theSecondInteger, theInputFileName, theOutputFileName);
            
        } catch (Exception ex) {
            writeToErrorLog("Unexpected error in main process: " + ex.getMessage());
            System.out.println("An unexpected error occurred. Please check the error log for details.");
        } finally {
            keyboardInput.close();
        }
    }
    
    private static String promptForValidName(String theNameType) {
        while (true) {
            System.out.println("\nPlease enter your " + theNameType + " name (max " + MAX_NAME_LENGTH + 
                             " characters, only letters, spaces, hyphens, and apostrophes allowed):");
            String userInput = keyboardInput.nextLine().trim();
            
            if (userInput.isEmpty()) {
                System.out.println("Error: Name cannot be empty. Please try again.");
                continue;
            }
            
            if (userInput.length() > MAX_NAME_LENGTH) {
                System.out.println("Error: Name exceeds maximum length of " + MAX_NAME_LENGTH + " characters. Please try again.");
                continue;
            }
            
            if (!VALID_NAME_PATTERN.matcher(userInput).matches()) {
                System.out.println("Error: Name contains invalid characters. Only letters, spaces, hyphens, and apostrophes are allowed.");
                continue;
            }
            
            return userInput;
        }
    }
    
    private static long promptForValidInteger(String thePosition) {
        while (true) {
            System.out.println("\nPlease enter the " + thePosition + " integer value (range: -2,147,483,648 to 2,147,483,647):");
            String userInput = keyboardInput.nextLine().trim();
            
            if (userInput.isEmpty()) {
                System.out.println("Error: Input cannot be empty. Please try again.");
                continue;
            }
            
            try {
                return Integer.parseInt(userInput);
            } catch (NumberFormatException ex) {
                System.out.println("Error: Invalid integer format. Please enter a valid number within the specified range.");
            }
        }
    }
    

    private static String promptForValidFileName(String theFileType) {
        while (true) {
            System.out.println("\nPlease enter the " + theFileType + " file name (must end with " + TEXT_FILE_EXTENSION + 
                             " and be in the current directory):");
            String fileName = keyboardInput.nextLine().trim();
            
            if (fileName.isEmpty()) {
                System.out.println("Error: File name cannot be empty. Please try again.");
                continue;
            }
            
            File fileObject = new File(fileName);
            if (!fileObject.getName().equals(fileName)) {
                System.out.println("Error: Path traversal is not allowed. Please provide only a file name.");
                continue;
            }
            
            if (!fileName.endsWith(TEXT_FILE_EXTENSION)) {
                System.out.println("Error: File must have " + TEXT_FILE_EXTENSION + " extension. Please try again.");
                continue;
            }
            
            if (theFileType.equals("input") && !Files.exists(Paths.get(fileName))) {
                System.out.println("Error: Input file does not exist. Please try again.");
                continue;
            }
            
            return fileName;
        }
    }
    
    private static void handlePasswordVerification() {
        String storedPasswordHash = null;
        byte[] storedPasswordSalt = null;
        
        try {
            if (Files.exists(Paths.get(HIDDEN_PASSWORD_FILE))) {
                String[] passwordFileData = new String(Files.readAllBytes(Paths.get(HIDDEN_PASSWORD_FILE))).split(":");
                if (passwordFileData.length == 2) {
                    storedPasswordHash = passwordFileData[0];
                    storedPasswordSalt = Base64.getDecoder().decode(passwordFileData[1]);
                }
            }
            
            if (storedPasswordHash == null || storedPasswordSalt == null) {
                createNewPassword();
                return;
            }
            
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
                }
            }
            
            if (!isPasswordCorrect) {
                System.out.println("Too many failed attempts. Creating a new password.");
                createNewPassword();
            }
            
        } catch (Exception ex) {
            writeToErrorLog("Error in password verification: " + ex.getMessage());
            System.out.println("An error occurred during password verification. Creating a new password.");
            createNewPassword();
        }
    }
    
    private static void createNewPassword() {
        boolean isPasswordSet = false;
        
        while (!isPasswordSet) {
            System.out.println("\nCreate a new password (minimum 8 characters, must include at least one uppercase letter, " +
                             "one lowercase letter, one digit, and one special character):");
            String newPassword = getPasswordFromUser();
            
            if (!isPasswordValid(newPassword)) {
                System.out.println("Password does not meet requirements. Please try again.");
                continue;
            }
            
            System.out.println("Confirm your password:");
            String confirmPassword = getPasswordFromUser();
            
            if (!newPassword.equals(confirmPassword)) {
                System.out.println("Passwords do not match. Please try again.");
                continue;
            }
            
            try {
                SecureRandom randomGenerator = new SecureRandom();
                byte[] passwordSalt = new byte[16];
                randomGenerator.nextBytes(passwordSalt);
                
                String hashedPassword = hashThePassword(newPassword, passwordSalt);
                
                String saltAsString = Base64.getEncoder().encodeToString(passwordSalt);
                Files.write(Paths.get(HIDDEN_PASSWORD_FILE), (hashedPassword + ":" + saltAsString).getBytes(),
                         StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                
                try {
                    File passwordFile = new File(HIDDEN_PASSWORD_FILE);
                    passwordFile.setReadable(false, false);
                    passwordFile.setReadable(true, true);
                    passwordFile.setWritable(false, false);
                    passwordFile.setWritable(true, true);
                } catch (Exception ex) {
                    writeToErrorLog("Could not set file permissions: " + ex.getMessage());
                }
                
                isPasswordSet = true;
                System.out.println("Password created and saved successfully.");
                
            } catch (Exception ex) {
                writeToErrorLog("Error creating password: " + ex.getMessage());
                System.out.println("An error occurred while saving the password. Please try again.");
            }
        }
    }
    

    private static String getPasswordFromUser() {
        Console consoleInput = System.console();
        if (consoleInput != null) {
            char[] passwordChars = consoleInput.readPassword();
            String enteredPassword = new String(passwordChars);
            Arrays.fill(passwordChars, ' ');  
            return enteredPassword;
        } else {
            return keyboardInput.nextLine();
        }
    }
    
    private static boolean isPasswordValid(String thePassword) {
        if (thePassword.length() < 8) {
            return false;
        }
        
        boolean hasUppercase = false;
        boolean hasLowercase = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        
        for (char currentChar : thePassword.toCharArray()) {
            if (Character.isUpperCase(currentChar)) {
                hasUppercase = true;
            } else if (Character.isLowerCase(currentChar)) {
                hasLowercase = true;
            } else if (Character.isDigit(currentChar)) {
                hasDigit = true;
            } else {
                hasSpecial = true;
            }
        }
        
        return hasUppercase && hasLowercase && hasDigit && hasSpecial;
    }
    

    private static String hashThePassword(String thePassword, byte[] theSalt) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(theSalt);
        byte[] hashedPasswordBytes = messageDigest.digest(thePassword.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashedPasswordBytes);
    }
    
    private static void processAndWriteFiles(String theFirstName, String theLastName, long theFirstInt, 
                                         long theSecondInt, String theInputFileName, String theOutputFileName) {
        try {
            BigInteger firstBigInt = BigInteger.valueOf(theFirstInt);
            BigInteger secondBigInt = BigInteger.valueOf(theSecondInt);
            BigInteger sumResult = firstBigInt.add(secondBigInt);
            BigInteger productResult = firstBigInt.multiply(secondBigInt);
            
            checkNumberForOverflow(sumResult, "Sum");
            checkNumberForOverflow(productResult, "Product");
            
            String inputFileContent = new String(Files.readAllBytes(Paths.get(theInputFileName)));
            
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
                
                System.out.println("\nProcessing complete. Data has been written to " + theOutputFileName);
            }
            
        } catch (Exception ex) {
            writeToErrorLog("Error processing files: " + ex.getMessage());
            System.out.println("An error occurred while processing the files. Please check the error log for details.");
        }
    }
    
    private static void checkNumberForOverflow(BigInteger theValue, String theOperation) {
        BigInteger minIntValue = BigInteger.valueOf(Integer.MIN_VALUE);
        BigInteger maxIntValue = BigInteger.valueOf(Integer.MAX_VALUE);
        
        if (theValue.compareTo(minIntValue) < 0 || theValue.compareTo(maxIntValue) > 0) {
            String errorMessage = theOperation + " would cause overflow! Value: " + theValue;
            writeToErrorLog(errorMessage);
            System.out.println("Warning: " + errorMessage);
            System.out.println("The calculation will continue using a larger data type.");
        }
    }
    
    private static void writeToErrorLog(String theErrorMessage) {
        try {
            if (!Files.exists(Paths.get(HIDDEN_ERROR_LOG_FILE))) {
                Files.createFile(Paths.get(HIDDEN_ERROR_LOG_FILE));
                
                File logFile = new File(HIDDEN_ERROR_LOG_FILE);
                logFile.setReadable(false, false);
                logFile.setReadable(true, true);
                logFile.setWritable(false, false);
                logFile.setWritable(true, true);
            }
            
            try (FileWriter fileWriter = new FileWriter(HIDDEN_ERROR_LOG_FILE, true);
                 BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                 PrintWriter printWriter = new PrintWriter(bufferedWriter)) {
                printWriter.println(java.time.LocalDateTime.now() + ": " + theErrorMessage);
            }
        } catch (Exception ex) {
            System.err.println("Failed to log error: " + ex.getMessage());
        }
    }
}