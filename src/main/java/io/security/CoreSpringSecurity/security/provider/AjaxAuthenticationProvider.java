package io.security.CoreSpringSecurity.security.provider;

import io.security.CoreSpringSecurity.security.service.AccountContext;
import io.security.CoreSpringSecurity.security.token.AjaxAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

public class AjaxAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    //검증을 위한 코드
    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // authentication에 아이디와 패스워드가 저장되어 있다.
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);
        if (!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        return new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
    }

    // authentication과 토큰의 타입이 일치할 때 인증처리를 할 수 있도록 조건을 준다
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AjaxAuthenticationToken.class);
    }
}
