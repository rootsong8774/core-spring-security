package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.AccountDTO;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }
    
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
        HttpServletResponse response)
        throws AuthenticationException, IOException, ServletException {
    
        if (!isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported.");
        }
    
        AccountDTO accountDTO = objectMapper.readValue(request.getReader(), AccountDTO.class);
        if (StringUtils.isEmpty(accountDTO.getUsername()) || StringUtils.isEmpty(
            accountDTO.getPassword())) {
            throw new IllegalArgumentException("Username or Password is empty");
        }
    
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(
            accountDTO.getUsername(), accountDTO.getPassword());
    
        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }
    
    private boolean isAjax(HttpServletRequest request) {
        return "XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
    }
}
