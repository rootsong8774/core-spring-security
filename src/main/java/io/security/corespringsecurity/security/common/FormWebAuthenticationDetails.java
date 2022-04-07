package io.security.corespringsecurity.security.common;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

public class FormWebAuthenticationDetails extends WebAuthenticationDetails {
    
    private final String secretKey;
    
    /**
     * Records the remote address and will also set the session Id if a session already exists (it won't
     * create one).
     *
     * @param request that the authentication request was received from
     */
    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("secret_key");
        System.out.println(secretKey);
    }
    
    public String getSecretKey() {
        return secretKey;
    }
}
