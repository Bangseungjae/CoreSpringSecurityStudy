package io.security.CoreSpringSecurity.service.impl;

import io.security.CoreSpringSecurity.domain.entity.Account;
import io.security.CoreSpringSecurity.repository.UserRepository;
import io.security.CoreSpringSecurity.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userService")
@AllArgsConstructor
public class UserServiceImpl implements UserService {

    private UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
