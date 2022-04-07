package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class AccountContext extends User {
    
    public AccountContext(Account account,
        Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(),account.getPassword(),authorities);
        
    }
}
