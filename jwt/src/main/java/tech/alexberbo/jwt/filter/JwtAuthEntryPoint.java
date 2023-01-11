package tech.alexberbo.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.stereotype.Component;
import tech.alexberbo.jwt.constants.SecurityConstants;
import tech.alexberbo.jwt.domain.httpResponse.HttpResponse;

import java.io.IOException;
import java.io.OutputStream;
import java.time.LocalDateTime;
import java.util.Date;

import static java.time.LocalDateTime.*;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static tech.alexberbo.jwt.constants.SecurityConstants.*;
@Component // BEAANZ
public class JwtAuthEntryPoint extends Http403ForbiddenEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        HttpResponse httpResponse = new HttpResponse(
                FORBIDDEN.value(),
                FORBIDDEN,
                FORBIDDEN.getReasonPhrase(),
                FORBIDDEN_MESSAGE,
                now().toString()
        ); // If user tries to enter something without auth, our custom response will pop up for the user that we made here.
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(FORBIDDEN.value());
        OutputStream outputStream = response.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(outputStream,  httpResponse);
        outputStream.flush();
    }
}
