package tech.alexberbo.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tech.alexberbo.jwt.filter.JwtAccessDeniedHandler;
import tech.alexberbo.jwt.filter.JwtAuthEntryPoint;
import tech.alexberbo.jwt.filter.JwtAuthFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;
import static tech.alexberbo.jwt.constants.SecurityConstants.NON_PUBLIC_URLS;
import static tech.alexberbo.jwt.constants.SecurityConstants.PUBLIC_URLS;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig { // SPRING 3.0.X CONFIGURATION - Authentication provider is a separate class now that checks the credentials and additional custom checks
    private final JwtAccessDeniedHandler accessDeniedHandler;
    private final JwtAuthEntryPoint entryPoint;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { // Stateless because we use our JWToken - any request has to be authorized, and it is going through our auth provider, our custom handlers and filters (checks if token is valid for the current user)

        http.csrf().disable().sessionManagement().sessionCreationPolicy(STATELESS).and()
                .authorizeHttpRequests()
                .requestMatchers(NON_PUBLIC_URLS).authenticated().and()
                .exceptionHandling().accessDeniedHandler(accessDeniedHandler).authenticationEntryPoint(entryPoint).and()
                .addFilterBefore(new JwtAuthFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web)->web.ignoring().requestMatchers(PUBLIC_URLS);
    }
}
