package tech.alexberbo.jwt.service;

import tech.alexberbo.jwt.domain.user.User;
import tech.alexberbo.jwt.exceptions.EmailExistsException;
import tech.alexberbo.jwt.exceptions.UserNotFoundException;
import tech.alexberbo.jwt.exceptions.UsernameExistsException;

import java.util.List;

public interface UserService { // i am not sure why is this implemented, maybe its better to have just one class that implements user detail service and repository
    User findUserByUsername(String username);
    User findUserByEmail(String email);
    List<User> getUsers();
    User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UsernameExistsException, EmailExistsException;
}
