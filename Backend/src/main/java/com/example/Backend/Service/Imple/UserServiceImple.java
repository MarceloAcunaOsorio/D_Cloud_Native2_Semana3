package com.example.Backend.Service.Imple;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.example.Backend.DTO.AlertDTO;
import com.example.Backend.DTO.JwtResponseDto;
import com.example.Backend.DTO.LoginDto;
import com.example.Backend.DTO.RegisterDto;
import com.example.Backend.DTO.UserDTO;
import com.example.Backend.Exceptions.ConflictException;
import com.example.Backend.Exceptions.JwtAuthenticationException;
import com.example.Backend.Exceptions.NotFoundException;
import com.example.Backend.Model.Alert;
import com.example.Backend.Model.Rol;
import com.example.Backend.Model.UserEntity;
import com.example.Backend.Repository.AlertRepository;
import com.example.Backend.Repository.UserRepository;
import com.example.Backend.Security.JwtGenerator;
import com.example.Backend.Service.RolService;
import com.example.Backend.Service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;

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
    @Autowired
    private AlertRepository alertRepository;
    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private ObjectMapper objectMapper;

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

    /**
     * Envía una alerta a la función Azure cuando se actualizan datos de usuarios
     * @param alertDTO Objeto que contiene la información de la alerta
     */
    private void sendAlertToFunction(AlertDTO alertDTO) {
        try {
            // URL de la función Azure (debe ser reemplazada con la URL real)
            String functionUrl = "YOUR_AZURE_FUNCTION_URL";
            
            // Configurar headers para la petición HTTP
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            // Crear el cuerpo de la petición con la alerta
            HttpEntity<String> request = new HttpEntity<>(
                objectMapper.writeValueAsString(alertDTO),
                headers
            );
            
            // Enviar la petición POST a la función Azure
            ResponseEntity<String> response = restTemplate.postForEntity(
                functionUrl,
                request,
                String.class
            );
            
            // Verificar si la petición fue exitosa
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("Error al enviar la alerta a la función Azure");
            }
        } catch (Exception e) {
            // Registrar el error pero no interrumpir el flujo principal
            System.err.println("Error al enviar alerta a la función Azure: " + e.getMessage());
        }
    }

    /**
     * Actualiza los datos de un cliente y genera una alerta si hay cambios
     * @param userDTO Objeto con los nuevos datos del cliente
     * @return AlertDTO con la información de la alerta generada
     */
    @Override
    public AlertDTO updateClient(UserDTO userDTO) {
        System.out.println("Intentando actualizar cliente: " + userDTO.getEmail());
        
        UserEntity user = userRepository.findByEmail(userDTO.getEmail())
            .orElseThrow(() -> new NotFoundException("Cliente no encontrado"));
        
        System.out.println("Roles del usuario: " + user.getRoles().stream()
            .map(Rol::getName)
            .collect(Collectors.joining(", ")));

        // Verificar si el usuario tiene rol de CLIENT
        if (!user.getRoles().stream().anyMatch(rol -> rol.getName().equals("USER"))) {
            throw new ConflictException("El usuario no es un cliente");
        }

        // Actualizar datos del usuario
        boolean hasChanges = false;
        StringBuilder changes = new StringBuilder();

        if (!user.getUsername().equals(userDTO.getUsername())) {
            changes.append("Nombre de usuario actualizado. ");
            user.setUsername(userDTO.getUsername());
            hasChanges = true;
        }

        if (userDTO.getPassword() != null && !userDTO.getPassword().isEmpty()) {
            changes.append("Contraseña actualizada. ");
            user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
            hasChanges = true;
        }

        // Guardar cambios del usuario
        userRepository.save(user);

        // Crear alerta si hubo cambios
        if (hasChanges) {
            Alert alert = new Alert();
            alert.setUser(user);
            alert.setMessage("Actualización de cliente: " + changes.toString());
            alert.setModificationType("UPDATE_CLIENT");
            alert.setCreatedAt(LocalDateTime.now());
            alert.setRead(false);
            Alert savedAlert = alertRepository.save(alert);

            AlertDTO alertDTO = convertToAlertDTO(savedAlert);
            sendAlertToFunction(alertDTO);
            return alertDTO;
        }

        return null;
    }

    /**
     * Actualiza los datos de un empleado y genera una alerta si hay cambios
     * @param userDTO Objeto con los nuevos datos del empleado
     * @return AlertDTO con la información de la alerta generada
     */
    @Override
    public AlertDTO updateEmployee(UserDTO userDTO) {
        UserEntity user = userRepository.findByEmail(userDTO.getEmail())
            .orElseThrow(() -> new NotFoundException("Empleado no encontrado"));
        
        // Verificar si el usuario tiene rol de EMPLOYEE
        if (!user.getRoles().stream().anyMatch(rol -> rol.getName().equals("EMPLOYEE"))) {
            throw new ConflictException("El usuario no es un empleado");
        }

        // Actualizar datos del usuario
        boolean hasChanges = false;
        StringBuilder changes = new StringBuilder();

        if (!user.getUsername().equals(userDTO.getUsername())) {
            changes.append("Nombre de usuario actualizado. ");
            user.setUsername(userDTO.getUsername());
            hasChanges = true;
        }

        if (userDTO.getPassword() != null && !userDTO.getPassword().isEmpty()) {
            changes.append("Contraseña actualizada. ");
            user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
            hasChanges = true;
        }

        // Guardar cambios del usuario
        userRepository.save(user);

        // Crear alerta si hubo cambios
        if (hasChanges) {
            Alert alert = new Alert();
            alert.setUser(user);
            alert.setMessage("Actualización de empleado: " + changes.toString());
            alert.setModificationType("UPDATE_EMPLOYEE");
            alert.setCreatedAt(LocalDateTime.now());
            alert.setRead(false);
            Alert savedAlert = alertRepository.save(alert);

            AlertDTO alertDTO = convertToAlertDTO(savedAlert);
            sendAlertToFunction(alertDTO);
            return alertDTO;
        }

        return null;
    }

    @Override
    public List<AlertDTO> getUserAlerts(Long userId) {
        UserEntity user = userRepository.findById(userId)
            .orElseThrow(() -> new NotFoundException("Usuario no encontrado"));
        
        List<Alert> alerts = alertRepository.findByUserOrderByCreatedAtDesc(user);
        return alerts.stream()
            .map(this::convertToAlertDTO)
            .collect(Collectors.toList());
    }

    @Override
    public List<AlertDTO> getAllAlerts() {
        List<Alert> alerts = alertRepository.findAllByOrderByCreatedAtDesc();
        return alerts.stream()
            .map(this::convertToAlertDTO)
            .collect(Collectors.toList());
    }

    @Override
    public void markAlertAsRead(Long alertId) {
        Alert alert = alertRepository.findById(alertId)
            .orElseThrow(() -> new NotFoundException("Alerta no encontrada"));
        alert.setRead(true);
        alertRepository.save(alert);
    }

    /**
     * Convierte un objeto Alert a AlertDTO para su transmisión
     * @param alert Objeto Alert a convertir
     * @return AlertDTO con la información convertida
     */
    private AlertDTO convertToAlertDTO(Alert alert) {
        AlertDTO alertDTO = new AlertDTO();
        alertDTO.setId(alert.getId());
        alertDTO.setMessage(alert.getMessage());
        alertDTO.setUserEmail(alert.getUser().getEmail());
        alertDTO.setUserRole(alert.getUser().getRoles().stream()
            .map(Rol::getName)
            .collect(Collectors.joining(", ")));
        alertDTO.setModificationType(alert.getModificationType());
        alertDTO.setCreatedAt(alert.getCreatedAt());
        alertDTO.setRead(alert.isRead());
        return alertDTO;
    }

}
