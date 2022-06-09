package io.security.CoreSpringSecurity.security.init;

import io.security.CoreSpringSecurity.security.service.RoleHierarchyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;

public class SecurityInitializer implements ApplicationRunner {

    @Autowired
    private RoleHierarchyService roleHierarchyService;

    @Autowired
    private RoleHierarchyImpl roleHierarchy;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        String allHierarchy = roleHierarchyService.findAllHierarchy();

        //기동할 때 포메팅된 권한 계층을 저장
       roleHierarchy.setHierarchy(allHierarchy);
    }
}
