package tech.alexberbo.jwt.utilities;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import tech.alexberbo.jwt.domain.user.UserClass;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static tech.alexberbo.jwt.constants.SecurityConstants.*;
@Component
public class JwtTokenGenerator { // Generating a token when a user logs in and authenticates successfully, making checks if the token is still valid, if it's not expired, encrypting the token, processing the request to the user if the user has passed the authentication
    @Value("${jwt.secret}")
    private String secret;

    public String generateJwtToken(UserClass user) { // Generating a token, issuer is who is giving the token, audience is to which audience, issuedAt is when was generated, Subject is to whom, ArrayClaims is users permissions, Expires at and sign with a big fat security algorithm
        String [] authorities = getUserAuthorities(user);
        return JWT.create().withIssuer(ALEXBERBO_RS).withAudience(ALEXBERBO_ADMINISTRATION).withIssuedAt(new Date())
                .withSubject(user.getUsername()).withArrayClaim(AUTHORITIES, authorities)
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(secret.getBytes()));
    }

    public Authentication getAuth(String username, List<GrantedAuthority> authorities, HttpServletRequest request) { // Builds the user information and sends them to spring context and telling spring that this user has passed the authentication and to process his request
        UsernamePasswordAuthenticationToken userPasswordAuthToken =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
        userPasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return userPasswordAuthToken;
    }

    public boolean isTokenValid (String username, String token) { // Checking if the token is still valid for a user
        JWTVerifier verifier = getJWTVerifier();
        return StringUtils.isEmpty(username) && !isTokenExpired(verifier, token);
    }

    public String getSubject(String token) { // Getting the subject (user) to whom the token belongs.
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getSubject();
    }
    private boolean isTokenExpired(JWTVerifier verifier, String token) { // Checking if the token is expired
        Date expirationDate = verifier.verify(token).getExpiresAt();
        return expirationDate.before(new Date());
    }

    private String[] getUserAuthorities(UserClass user) { // Get authorities for a user that signs in, last line i dont get TO DO investigate
        List<String> authorities = new ArrayList<>();
        for(GrantedAuthority grantedAuthority : user.getAuthorities()) {
            authorities.add(grantedAuthority.getAuthority());
        }
        return authorities.toArray(new String[0]);
    }
    public List<GrantedAuthority> getAuthorities(String token) { // STEP 3: Mapping the authorities to assign to a user role
        String[] authorities = getAuthoritiesFromToken(token);
        return stream(authorities).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    private String[] getAuthoritiesFromToken(String token) { // STEP 2: Getting the authorities of a user through a verified token that the user received
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
    }

    private JWTVerifier getJWTVerifier() { // STEP 1: Creating a verifier that will verify a token's validity!!!
        JWTVerifier verifier;
        try {
            Algorithm algorithm = Algorithm.HMAC512(secret);
            verifier = JWT.require(algorithm).withIssuer(ALEXBERBO_RS).build();
        } catch(JWTVerificationException ex) {
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }
        return verifier;
    }
}
