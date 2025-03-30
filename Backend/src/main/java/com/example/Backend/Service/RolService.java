package com.example.Backend.Service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.example.Backend.Model.Rol;

@Service
public interface RolService {
    
     public Optional<Rol> findByname(String name);
}
