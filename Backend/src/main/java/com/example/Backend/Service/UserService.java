package com.example.Backend.Service;

import java.util.List;

import org.springframework.http.HttpHeaders;

import com.example.Backend.DTO.JwtResponseDto;
import com.example.Backend.DTO.LoginDto;
import com.example.Backend.DTO.RegisterDto;
import com.example.Backend.DTO.UserDTO;

public interface  UserService {
    
    //registrar cliente
    public UserDTO register(RegisterDto registerDto);
    //login
    public JwtResponseDto login(LoginDto loginDto);
    //obtener usuario logueado
    UserDTO getLoguedUser(HttpHeaders headers);
    //registrar empleado
    public UserDTO registerEmployee(RegisterDto registerDto);

    //obtener todos los usuarios
    List<UserDTO> getAllUsers();

    //obtener usuario por id
    UserDTO getUserById(Long id);

    //actualizar usuario
    UserDTO updateUser(UserDTO userDTO);

    //eliminar usuario
    void deleteUser(Long id);
}
