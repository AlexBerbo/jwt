package tech.alexberbo.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import org.springframework.stereotype.Component;
import tech.alexberbo.jwt.domain.httpResponse.HttpResponse;

import java.io.IOException;
import java.io.OutputStream;

import static java.time.LocalDateTime.*;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.*;
import static tech.alexberbo.jwt.constants.SecurityConstants.*;
@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler { // Exception that is thrown when a user has not logged in and tries to enter something he is not allowed to
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        HttpResponse httpResponse = new HttpResponse(
                UNAUTHORIZED.value(),
                UNAUTHORIZED,
                UNAUTHORIZED.getReasonPhrase(),
                ACCESS_DENIED_MESSAGE,
                now().toString()
        );
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(UNAUTHORIZED.value());
        OutputStream outputStream = response.getOutputStream(); // Write the data(message) get it and put it into a json format we made.
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(outputStream, httpResponse);
        outputStream.flush();
    }
}
