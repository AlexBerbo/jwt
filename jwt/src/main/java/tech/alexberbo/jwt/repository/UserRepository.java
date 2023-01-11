package tech.alexberbo.jwt.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.JpaRepository;
import tech.alexberbo.jwt.domain.user.User;

import java.awt.print.Pageable;

public interface UserRepository extends JpaRepository<User, Long> { // Data queries for getting user data, and pagination
    //public Page<User> findByUsernameContaining(String username, Pageable pageable);
    public User findUserByUsername (String username);
    public User findUserByEmail (String email);
}
