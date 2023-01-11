package tech.alexberbo.jwt.exceptions;

public class UsernameExistsException extends Exception {
    public UsernameExistsException(String message) {
        super(message);
    }
}
