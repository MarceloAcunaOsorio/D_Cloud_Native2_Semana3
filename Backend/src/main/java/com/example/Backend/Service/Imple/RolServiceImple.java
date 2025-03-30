package com.example.Backend.Service.Imple;


import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.Backend.Model.Rol;
import com.example.Backend.Repository.RoleRepository;
import com.example.Backend.Service.RolService;

@Service
public class RolServiceImple implements RolService{
    
     @Autowired
    private RoleRepository roleRepository;
    @Override
    public Optional<Rol> findByname(String name) {
        return roleRepository.findByName(name);
    }
}
