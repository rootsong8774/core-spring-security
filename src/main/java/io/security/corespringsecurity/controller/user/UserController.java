package io.security.corespringsecurity.controller.user;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.AccountDTO;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserService userService;
    
    @GetMapping("/mypage")
    public String myPage() {
        return "user/mypage";
    }
    
    @GetMapping("/users")
    public String createUser() {
        return "user/login/register";
    }
    
    @PostMapping("/users")
    public String createUser(AccountDTO accountDTO) {
        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDTO, Account.class);
        account.setPassword(passwordEncoder.encode(account.getPassword()));
        userService.createUser(account);
    
        return "redirect:/";
    }
}
