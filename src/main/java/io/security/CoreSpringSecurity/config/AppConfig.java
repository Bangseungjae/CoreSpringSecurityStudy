package io.security.CoreSpringSecurity.config;

import io.security.CoreSpringSecurity.repository.AccessIpRepository;
import io.security.CoreSpringSecurity.repository.ResourcesRepository;
import io.security.CoreSpringSecurity.security.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository, AccessIpRepository accessIpRepository) {
        return new SecurityResourceService(resourcesRepository, accessIpRepository);
    }
}
