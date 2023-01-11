package tech.alexberbo.jwt.service.impl;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import tech.alexberbo.jwt.domain.user.User;
import tech.alexberbo.jwt.domain.user.UserClass;
import tech.alexberbo.jwt.enumerators.UserRole;
import tech.alexberbo.jwt.exceptions.EmailExistsException;
import tech.alexberbo.jwt.exceptions.UserNotFoundException;
import tech.alexberbo.jwt.exceptions.UsernameExistsException;
import tech.alexberbo.jwt.repository.UserRepository;
import tech.alexberbo.jwt.service.UserService;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.apache.commons.lang3.StringUtils.*;
import static tech.alexberbo.jwt.enumerators.UserRole.*;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService { // Implementation of user service and our repository, so we can use our queries, logic to find a user that is being logged in
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username);
        if (user == null) {
            log.info("User with " + username + " not found!");
            throw new UsernameNotFoundException("User with " + username + " not found!");
        }
        user.setLastLoginDateDisplay(user.getLastLoginDate());
        user.setLastLoginDate(new Date());
        userRepository.save(user);
        UserClass userClass = new UserClass(user);
        log.info("Found user " + username);
        return userClass;
    }

    @Override
    public User findUserByUsername(String username) {
        return userRepository.findUserByUsername(username);
    }

    @Override
    public User findUserByEmail(String email) {
        return userRepository.findUserByEmail(email);
    }

    @Override
    public List<User> getUsers() {
        return null;
    }

    @Override
    public User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UsernameExistsException, EmailExistsException {
        validateNewUsernameAndEmail(EMPTY, username, email);
        User user = new User();
        String password = generatePassword();
        String encodedPw= passwordEncoder.encode(password);
        user.setUserId(generateUserId());
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(encodedPw);
        user.setProfileImageUrl(getImageUrl());
        user.setJoinedDate(new Date());
        user.setRoles(ROLE_USER.name());
        user.setAuthorities(ROLE_USER.getAuthorities());
        user.setActive(true);
        user.setNotLocked(true);
        userRepository.save(user);
        log.info("Password: " + password);
        return user;
    }

    private String generateUserId() {
        return UUID.randomUUID().toString();
    }

    private String generatePassword() {
        return UUID.randomUUID().toString();
    }

    private String getImageUrl() {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/demoaopp/image/temp").toUriString();
    }

    private User validateNewUsernameAndEmail(String currentUserName, String newUsername, String newEmail) throws UserNotFoundException, UsernameExistsException, EmailExistsException {
        if(isNotBlank(currentUserName)) {
            User currentUser = findUserByUsername(currentUserName);
            if(currentUser == null) {
                throw new UserNotFoundException(currentUser + " not found!");
            }
            User userByUsername = findUserByUsername(newUsername);
            if(userByUsername != null && !currentUser.getUserId().equals(userByUsername.getUserId())) {
                throw new UsernameExistsException(userByUsername + " already exists");
            }
            User userByEmail = findUserByEmail(newEmail);
            if(userByEmail != null && !currentUser.getUserId().equals(userByEmail.getUserId())) {
                throw new EmailExistsException(userByEmail + " already exists");
            }
            return currentUser;
        } else {
            User userByUsername = findUserByUsername(newUsername);
            if(userByUsername != null) {
                throw new UsernameExistsException(userByUsername + " already exists");
            }
            User userByEmail = findUserByEmail(newEmail);
            if(userByEmail != null) {
                throw new EmailExistsException(userByEmail + " already exists");
            }
            return null;
        }
    }
}
