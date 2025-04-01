// Paquete que contiene la implementación del servicio de roles
package com.example.Backend.Service.Imple;

// Importación para manejar valores opcionales
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.Backend.Model.Rol;
import com.example.Backend.Repository.RoleRepository;
import com.example.Backend.Service.RolService;

// Servicio que implementa la lógica de negocio para los roles
@Service
public class RolServiceImple implements RolService{
    
    // Inyección automática del repositorio de roles
    @Autowired
    private RoleRepository roleRepository;

    // Método que busca un rol por su nombre
    @Override
    public Optional<Rol> findByname(String name) {
        // Retorna un Optional que puede contener el rol si existe
        return roleRepository.findByName(name);
    }
}
