package io.security.CoreSpringSecurity.security.service;

import io.security.CoreSpringSecurity.domain.entity.Account;
import io.security.CoreSpringSecurity.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@AllArgsConstructor
@Service
@Slf4j
public class CustomUserDetails implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username);

        if (account == null) {
            throw new UsernameNotFoundException("UsernameNotFountException");
        }
        List<GrantedAuthority> roles = new ArrayList<>();

        roles.add(new SimpleGrantedAuthority(account.getUserRoles().toString()));
        AccountContext accountContext = new AccountContext(account, roles);

        return accountContext;
    }
}
