package tech.alexberbo.jwt.exceptions;

import com.auth0.jwt.exceptions.TokenExpiredException;
import jakarta.persistence.NoResultException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.PermissionDeniedDataAccessException;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import tech.alexberbo.jwt.domain.httpResponse.HttpResponse;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Objects;

import static org.springframework.http.HttpStatus.*;

@RestControllerAdvice
@Slf4j
public class ExceptionHandling {
    public static final String ACCOUNT_LOCKED = "Your account has been locked, please contact the administrator @ berbo997@gmail.com.";
    public static final String METHOD_IS_NOT_ALLOWED = "This request method is not allowed. Please send '%s' request.";
    public static final String INTERNAL_SERVER_ERROR_MSG = "An error occurred while processing the request.";
    public static final String INCORRECT_CREDENTIALS = "Username / Password incorrect. Please provide the right credentials.";
    public static final String ACCOUNT_DISABLED = "Your account has been disabled, please contact the administrator @ berbo997@gmail.com.";
    public static final String ERROR_PROCESSING_FILE = "An error occurred while processing file.";
    public static final String NOT_ENOUGH_PERMISSION = "You do not have enough permissions.";
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<HttpResponse> accessDeniedException() {
        return createHttpResponse(FORBIDDEN, NOT_ENOUGH_PERMISSION);
    }
    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<HttpResponse> tokenExpiredException(TokenExpiredException exception) {
        return createHttpResponse(UNAUTHORIZED  , exception.getMessage());
    }
    @ExceptionHandler(LockedException.class)
    public ResponseEntity<HttpResponse> accountLockedException() {
        return createHttpResponse(UNAUTHORIZED, ACCOUNT_LOCKED);
    }
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<HttpResponse> methodNotAllowedException(HttpRequestMethodNotSupportedException exception) {
        HttpMethod method = Objects.requireNonNull(exception.getSupportedHttpMethods()).iterator().next();
        return createHttpResponse(METHOD_NOT_ALLOWED, String.format(METHOD_IS_NOT_ALLOWED, method));
    }
    @ExceptionHandler(Exception.class)
    public ResponseEntity<HttpResponse> internalServerErrorException(Exception exception) {
        log.error(exception.getMessage());
        return createHttpResponse(INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_MSG);
    }
    @ExceptionHandler(NoResultException.class)
    public ResponseEntity<HttpResponse> notFoundException(Exception exception) {
        log.error(exception.getMessage());
        return createHttpResponse(NOT_FOUND, exception.getMessage());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<HttpResponse> incorrectCredentialsException() {
        return createHttpResponse(BAD_REQUEST, INCORRECT_CREDENTIALS);
    }
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<HttpResponse> accountDisabledException() {
        return createHttpResponse(BAD_REQUEST, ACCOUNT_DISABLED);
    }
    @ExceptionHandler(IOException.class)
    public ResponseEntity<HttpResponse> iOException(IOException exception) {
        log.error(exception.getMessage());
        return createHttpResponse(INTERNAL_SERVER_ERROR, ERROR_PROCESSING_FILE);
    }
    @ExceptionHandler(PermissionDeniedDataAccessException.class)
    public ResponseEntity<HttpResponse> notEnoughPermission() {
        return createHttpResponse(UNAUTHORIZED, NOT_ENOUGH_PERMISSION);
    }
    @ExceptionHandler(EmailExistsException.class)
    public ResponseEntity<HttpResponse> emailExistsException(EmailExistsException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }
    @ExceptionHandler(UsernameExistsException.class)
    public ResponseEntity<HttpResponse> usernameExistsException(UsernameExistsException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }
    @ExceptionHandler(EmailNotFoundException.class)
    public ResponseEntity<HttpResponse> emailNotFoundException(EmailNotFoundException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<HttpResponse> usernameNotFoundException(UserNotFoundException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }
    private ResponseEntity<HttpResponse> createHttpResponse(HttpStatus status, String message) {
        return new ResponseEntity<>(new HttpResponse(
                status.value(),
                status,
                status.getReasonPhrase().toUpperCase(),
                message.toUpperCase(),
                LocalDateTime.now().toString()), status);
    }
}
