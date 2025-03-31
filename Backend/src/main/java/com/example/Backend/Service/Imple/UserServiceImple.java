package com.example.Backend.Service.Imple;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.Backend.Model.Rol;
import com.example.Backend.Model.UserEntity;
import com.example.Backend.Repository.UserRepository;
import com.example.Backend.Service.RolService;
import com.example.Backend.Service.UserService;
import com.example.Backend.DTO.JwtResponseDto;
import com.example.Backend.DTO.LoginDto;
import com.example.Backend.DTO.RegisterDto;
import com.example.Backend.DTO.UserDTO;
import com.example.Backend.Exceptions.ConflictException;
import com.example.Backend.Security.JwtGenerator;
import com.example.Backend.Exceptions.JwtAuthenticationException;
import com.example.Backend.Exceptions.NotFoundException;

@Service
public class UserServiceImple implements UserService{
    
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RolService rolService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtGenerator jwtGenerator;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDTO register(RegisterDto registerDto) {
        if (userRepository.existsByEmail(registerDto.getEmail())){
            throw new ConflictException("El usuario existe!");
        }
        UserEntity user = new UserEntity();
        user.setUsername(registerDto.getUsername());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));
        user.setEmail(registerDto.getEmail());

        Rol rol = rolService.findByname("USER").orElseThrow(()-> new NotFoundException("Rol no encontrado!"));
        Set<Rol> roles = new HashSet<>();
        roles.add(rol);
        user.setRoles(roles);
        userRepository.save(user);

        UserDTO userDto = new UserDTO();
        userDto.setUsername(user.getUsername());
        userDto.setPassword(user.getPassword());
        userDto.setEmail(user.getEmail());
        userDto.setRoles(user.getRoles());
        return userDto;
    }

    @Override
    public UserDTO registerEmployee(RegisterDto registerDto) {
        if (userRepository.existsByEmail(registerDto.getEmail())){
            throw new ConflictException("El usuario existe!");
        }
        UserEntity user = new UserEntity();
        user.setUsername(registerDto.getUsername());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));
        user.setEmail(registerDto.getEmail());

        Rol rol = rolService.findByname("EMPLOYEE").orElseThrow(()-> new NotFoundException("Rol no encontrado!"));
        Set<Rol> roles = new HashSet<>();
        roles.add(rol);
        user.setRoles(roles);
        userRepository.save(user);

        UserDTO userDto = new UserDTO();
        userDto.setUsername(user.getUsername());
        userDto.setPassword(user.getPassword());
        userDto.setEmail(user.getEmail());
        userDto.setRoles(user.getRoles());
        return userDto;
    }

    @Override
    public JwtResponseDto login(LoginDto loginDto) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginDto.getEmail(),
                            loginDto.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String token = jwtGenerator.generateToken(authentication);
            return new JwtResponseDto(token);
        } catch (AuthenticationException e) {
            throw new JwtAuthenticationException("Credenciales inválidas");
        }
    }

    @Override
    public UserDTO getLoguedUser(HttpHeaders headers) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String email = ((UserEntity) authentication.getPrincipal()).getUsername();

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(()-> new NotFoundException("Usuario no encontrado"));
        UserDTO userDto = new UserDTO();
        userDto.setEmail(user.getEmail());
        userDto.setUsername(user.getUsername());
        userDto.setRoles(user.getRoles());
        return userDto;
    }

    @Override
    public List<UserDTO> getAllUsers() {
        List<UserEntity> users = userRepository.findAll();
        return users.stream()
            .map(user -> {
                UserDTO userDto = new UserDTO();
                userDto.setEmail(user.getEmail());
                userDto.setUsername(user.getUsername());
                userDto.setRoles(user.getRoles());
                return userDto;
            })
            .collect(Collectors.toList());
    }

    @Override
    public UserDTO getUserById(Long id) {
        UserEntity user = userRepository.findById(id)
            .orElseThrow(() -> new NotFoundException("Usuario no encontrado con ID: " + id));
        
        UserDTO userDto = new UserDTO();
        userDto.setEmail(user.getEmail());
        userDto.setUsername(user.getUsername());
        userDto.setRoles(user.getRoles());
        return userDto;
    }

    @Override
    public UserDTO updateUser(UserDTO userDTO) {
        UserEntity user = userRepository.findByEmail(userDTO.getEmail())
            .orElseThrow(() -> new NotFoundException("Usuario no encontrado"));
        
        user.setUsername(userDTO.getUsername());
        if (userDTO.getPassword() != null && !userDTO.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        }
        
        if (userDTO.getRoles() != null && !userDTO.getRoles().isEmpty()) {
            user.setRoles(userDTO.getRoles());
        }
        
        UserEntity updatedUser = userRepository.save(user);
        
        UserDTO updatedUserDto = new UserDTO();
        updatedUserDto.setEmail(updatedUser.getEmail());
        updatedUserDto.setUsername(updatedUser.getUsername());
        updatedUserDto.setRoles(updatedUser.getRoles());
        return updatedUserDto;
    }

    @Override
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new NotFoundException("Usuario no encontrado con ID: " + id);
        }
        userRepository.deleteById(id);
    }

}
