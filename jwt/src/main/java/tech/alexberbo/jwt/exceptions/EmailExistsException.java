package tech.alexberbo.jwt.exceptions;

public class EmailExistsException extends Exception {
    public EmailExistsException(String message) {
        super(message);
    }
}
