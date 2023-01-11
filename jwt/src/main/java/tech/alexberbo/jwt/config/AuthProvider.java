package tech.alexberbo.jwt.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import tech.alexberbo.jwt.service.impl.UserServiceImpl;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthProvider extends AbstractUserDetailsAuthenticationProvider {
    private final UserServiceImpl userService;
    private final BCryptPasswordEncoder passwordEncoder;
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        if(authentication.getCredentials() == null || userDetails.getPassword() == null) {
            log.info("Credentials may be null - " + authentication.getCredentials());
            throw new BadCredentialsException("Credentials may be null");
        }

        if(!passwordEncoder.matches((String) authentication.getCredentials(), userDetails.getPassword())) {
            log.info("Invalid Credentials");
            throw new BadCredentialsException("Invalid Credentials");
        }
     }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        return userService.loadUserByUsername(username);
    }
}
