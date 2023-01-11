package tech.alexberbo.jwt.domain.httpResponse;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@Setter
@AllArgsConstructor
public class HttpResponse {
    private int statusCode;
    private HttpStatus status;
    private String reason;
    private String message;
    private String timeStamp;
}
