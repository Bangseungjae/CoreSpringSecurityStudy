package io.security.CoreSpringSecurity.aopsecurity;

import org.springframework.stereotype.Service;

@Service
public class AopMethodService {

    public void methodSecured() {
        System.out.println("methodSecured");
    }
}
