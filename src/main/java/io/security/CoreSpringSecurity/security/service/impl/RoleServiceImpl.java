package io.security.CoreSpringSecurity.security.service.impl;

import io.security.CoreSpringSecurity.domain.entity.Role;
import io.security.CoreSpringSecurity.repository.RoleRepository;
import io.security.CoreSpringSecurity.security.service.RoleService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

@Slf4j
@Service
public class RoleServiceImpl implements RoleService {

    @Autowired
    private RoleRepository roleRepository;

    @Transactional
    public Role getRole(long id) {
        return roleRepository.findById(id).orElse(new Role());
    }

    @Transactional
    public List<Role> getRoles() {

        return roleRepository.findAll();
    }

    @Transactional
    public void createRole(Role role){

        roleRepository.save(role);
    }

    @Transactional
    public void deleteRole(long id) {
        roleRepository.deleteById(id);
    }
}
