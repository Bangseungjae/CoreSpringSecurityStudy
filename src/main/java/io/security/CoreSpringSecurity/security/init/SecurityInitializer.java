package io.security.CoreSpringSecurity.security.init;

import io.security.CoreSpringSecurity.security.service.RoleHierarchyService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class SecurityInitializer implements ApplicationRunner {

    @Autowired
    private RoleHierarchyService roleHierarchyService;

    @Autowired
    private RoleHierarchyImpl roleHierarchy;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.info("Runner start");
        String allHierarchy = roleHierarchyService.findAllHierarchy();

        log.info("runner allHierarchy={}", allHierarchy);

        //기동할 때 포메팅된 권한 계층을 저장
       roleHierarchy.setHierarchy(allHierarchy);
    }
}
