package io.security.CoreSpringSecurity.controller.user;

import io.security.CoreSpringSecurity.domain.entity.Account;
import io.security.CoreSpringSecurity.domain.dto.AccountDto;
import io.security.CoreSpringSecurity.service.UserService;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@AllArgsConstructor
public class UserController {


    private final PasswordEncoder passwordEncoder;
    private final UserService userService;


    @GetMapping("/mypage")
    public String myPage() {
        return "user/mypage";
    }

    @GetMapping("/users")
    public String createUser() {
        return "user/login/register";
    }

    @PostMapping("/users")
    public String createUser(AccountDto accountDto) {
        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);
        account.setPassword(passwordEncoder.encode(account.getPassword()));// 패스워드 암호화해서 변경
        userService.createUser(account);

        return "redirect:/";
    }
}
