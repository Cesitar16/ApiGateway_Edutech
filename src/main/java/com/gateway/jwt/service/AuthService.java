package com.gateway.jwt.service;

import com.gateway.jwt.dto.*;
import com.gateway.jwt.model.Usuario;
import com.gateway.jwt.repository.UsuarioRepository;
import com.gateway.jwt.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UsuarioRepository usuarioRepository;
    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;

    public AuthResponse login(LoginRequest request) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        Usuario usuario = usuarioRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        if (!usuario.getActivo()) {
            throw new IllegalStateException("Usuario inactivo");
        }

        String token = jwtUtil.generateToken(usuario.getUsername(), usuario.getRol().getNombreRol());
        return new AuthResponse(token, usuario.getUsername(), usuario.getRol().getNombreRol());
    }
}
