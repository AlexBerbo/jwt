package tech.alexberbo.jwt.resource;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.alexberbo.jwt.domain.user.User;
import tech.alexberbo.jwt.exceptions.EmailExistsException;
import tech.alexberbo.jwt.exceptions.ExceptionHandling;
import tech.alexberbo.jwt.exceptions.UserNotFoundException;
import tech.alexberbo.jwt.exceptions.UsernameExistsException;
import tech.alexberbo.jwt.service.UserService;

import static org.springframework.http.HttpStatus.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserResource extends ExceptionHandling { // Exceptions that we will use in case something goes wrong, we need them to hide our app detail so hackers can not reverse engineer our code.
    private final UserService userService;
    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody String firstName, String lastName, String email, String username) throws EmailExistsException, UserNotFoundException, UsernameExistsException {
        User newUser = userService.register(firstName, lastName, email, username);
        return new ResponseEntity<>(newUser, CREATED);
    }
}
