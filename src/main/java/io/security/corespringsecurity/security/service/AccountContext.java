package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

@Getter
@Setter
public class AccountContext extends User {
    
    private Account account;
    
    public AccountContext(Account account, List<GrantedAuthority> roles) {
        super(account.getUsername(), account.getPassword(), roles);
        this.account = account;
    }
}
