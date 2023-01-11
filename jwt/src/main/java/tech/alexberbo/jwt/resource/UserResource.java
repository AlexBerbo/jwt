package tech.alexberbo.jwt.resource;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import tech.alexberbo.jwt.config.AuthProvider;
import tech.alexberbo.jwt.domain.user.User;
import tech.alexberbo.jwt.domain.user.UserClass;
import tech.alexberbo.jwt.exceptions.EmailExistsException;
import tech.alexberbo.jwt.exceptions.ExceptionHandling;
import tech.alexberbo.jwt.exceptions.UserNotFoundException;
import tech.alexberbo.jwt.exceptions.UsernameExistsException;
import tech.alexberbo.jwt.service.UserService;
import tech.alexberbo.jwt.utilities.JwtTokenGenerator;

import static org.springframework.http.HttpStatus.*;
import static tech.alexberbo.jwt.constants.SecurityConstants.JWT_TOKEN_HEADER;

@RestController
@AllArgsConstructor
@RequestMapping("/user")
public class UserResource extends ExceptionHandling { // Exceptions that we will use in case something goes wrong, we need them to hide our app detail so hackers can not reverse engineer our code.
    private UserService userService;
    private JwtTokenGenerator jwtTokenGenerator;
    private AuthProvider authProvider;
    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user) {
        authenticate(user.getUsername(), user.getPassword());
        User loginUser = userService.findUserByUsername(user.getUsername());
        UserClass userClass = new UserClass(loginUser);
        HttpHeaders jwtHeader = jwtHeaderGenerator(userClass);
        return new ResponseEntity<>(loginUser, jwtHeader, CREATED);
    }

    private void authenticate(String username, String password) {
        authProvider.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }

    private HttpHeaders jwtHeaderGenerator(UserClass user) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenGenerator.generateJwtToken(user));
        return headers;
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) throws EmailExistsException, UserNotFoundException, UsernameExistsException {
        User newUser = userService.register(user.getFirstName(), user.getLastName(), user.getUsername(), user.getEmail());
        return new ResponseEntity<>(newUser, CREATED);
    }

    @GetMapping("/demoapp/welcome")
    public String welcome() {
        return "Hello";
    }
}
