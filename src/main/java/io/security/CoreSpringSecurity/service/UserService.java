package io.security.CoreSpringSecurity.service;

import io.security.CoreSpringSecurity.domain.entity.Account;

public interface UserService {

    void createUser(Account account);

    void order();
}
