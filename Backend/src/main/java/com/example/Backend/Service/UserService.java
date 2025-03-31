package com.example.Backend.Service;

import org.springframework.http.HttpHeaders;

import com.example.Backend.DTO.JwtResponseDto;
import com.example.Backend.DTO.LoginDto;
import com.example.Backend.DTO.RegisterDto;
import com.example.Backend.DTO.UserDTO;

public interface  UserService {
    
    public UserDTO register(RegisterDto registerDto);
    public JwtResponseDto login(LoginDto loginDto);
    UserDTO getLoguedUser(HttpHeaders headers);
    public UserDTO registerEmployee(RegisterDto registerDto);
}
