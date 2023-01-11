package tech.alexberbo.jwt.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.alexberbo.jwt.utilities.JwtTokenGenerator;

import java.io.IOException;
import java.util.List;

import static tech.alexberbo.jwt.constants.SecurityConstants.*;
@RequiredArgsConstructor
@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    private JwtTokenGenerator jwtTokenGenerator;
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if(request.getMethod().equalsIgnoreCase(OPTIONS_HTTP_MESSAGE)) { // let the request through if it's not get/post/put/delete
            response.setStatus(HttpStatus.OK.value());
        } else { // getting the token from the header and checking if it's not null and if it starts with the prefix Bearer
            String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            if(authorizationHeader == null && !authorizationHeader.startsWith(TOKEN_PREFIX)) { // if the token is null, or it does not start with Bearer prefix, let it go we don't want to work with it
                filterChain.doFilter(request, response);
                return;
            }
            String token = authorizationHeader.substring(TOKEN_PREFIX.length()); // stripping prefix from the token and getting the actual token
            String username = jwtTokenGenerator.getSubject(token); // getting the user's username
            if(jwtTokenGenerator.isTokenValid(username, token) && SecurityContextHolder.getContext().getAuthentication() == null) { // if the token is valid and user has not been authenticated, get the authorities for that user and set the user to user authenticated and process his request
                List<GrantedAuthority> authorities = jwtTokenGenerator.getAuthorities(token);
                Authentication authentication = jwtTokenGenerator.getAuth(username, authorities, request);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else { // if the token is not valid or the user has already some auth going on, clear the spring security context and try again.
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request, response); //TO DO investigate:: if the token is valid and no previous authentications have been found, let the user in
    }
}
