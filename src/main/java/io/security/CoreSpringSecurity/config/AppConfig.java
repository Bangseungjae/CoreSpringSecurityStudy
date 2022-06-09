package io.security.CoreSpringSecurity.config;

import io.security.CoreSpringSecurity.repository.ResourcesRepository;
import io.security.CoreSpringSecurity.security.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository) {
        return new SecurityResourceService(resourcesRepository);
    }
}
