package io.security.CoreSpringSecurity.repository;

import io.security.CoreSpringSecurity.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {

    public Account findByUsername(String username);

    public Account findByUsernameAndPassword(String username, String password);
}
