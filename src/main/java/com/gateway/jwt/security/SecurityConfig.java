package com.gateway.jwt.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.gateway.redireccion.carritos.CarritoPublicRoutes;
import com.gateway.redireccion.comentarios.ComentariosPublicRoutes;
import com.gateway.redireccion.cupones.CuponesPublicRoutes;
import com.gateway.redireccion.cursos.CursosPublicRoutes;
import com.gateway.redireccion.pagos.PagosPublicRoutes;
import com.gateway.redireccion.roles.RolesPublicRoutes;
import com.gateway.redireccion.soporte.SoportePublicRoutes;
import com.gateway.redireccion.ubicacion.UbicacionPublicRoutes;
import com.gateway.redireccion.usuarios.UsuariosPublicRoutes;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import org.springframework.http.HttpMethod; // Import necesario

import static com.gateway.jwt.security.PublicRoutes.*;           // rutas públicas JWT

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, PUBLIC_POST).permitAll() // Rutas públicas POST
                .requestMatchers(HttpMethod.GET, PUBLIC_GET).permitAll()   // Rutas públicas GET
                .requestMatchers(HttpMethod.GET, RolesPublicRoutes.ROLES_PUBLIC_GET).permitAll()
                .requestMatchers(HttpMethod.GET, CuponesPublicRoutes.CUPONES_PUBLIC_GET).permitAll()
                .requestMatchers(HttpMethod.GET, UsuariosPublicRoutes.USUARIOS_PUBLIC_GET).permitAll()
                .requestMatchers(HttpMethod.POST, UsuariosPublicRoutes.USUARIOS_PUBLIC_POST).permitAll()
                .requestMatchers(HttpMethod.GET, CarritoPublicRoutes.CARRITOS_PUBLIC_GET).permitAll()
                .requestMatchers(HttpMethod.POST, CarritoPublicRoutes.CARRITOS_PUBLIC_POST).permitAll()
                .requestMatchers(HttpMethod.GET, ComentariosPublicRoutes.COMENTARIOS_PUBLIC_GET).permitAll()
                .requestMatchers(HttpMethod.POST, ComentariosPublicRoutes.COMENTARIOS_PUBLIC_POST).permitAll()
                .requestMatchers(HttpMethod.GET, CursosPublicRoutes.CURSOS_PUBLIC_GET).permitAll()
                .requestMatchers(HttpMethod.POST, CursosPublicRoutes.CURSOS_PUBLIC_POST).permitAll()
                .requestMatchers(HttpMethod.GET, PagosPublicRoutes.PAGOS_PUBLIC_GET).permitAll()
                .requestMatchers(HttpMethod.POST, PagosPublicRoutes.PAGOS_PUBLIC_POST).permitAll()
                .requestMatchers(HttpMethod.GET, SoportePublicRoutes.SOPORTE_PUBLIC_GET).permitAll()
                .requestMatchers(HttpMethod.POST, SoportePublicRoutes.SOPORTE_PUBLIC_POST).permitAll()
                .requestMatchers(HttpMethod.GET, UbicacionPublicRoutes.UBICACION_PUBLIC_GET).permitAll()
                .requestMatchers(HttpMethod.POST, UbicacionPublicRoutes.UBICACION_PUBLIC_POST).permitAll()
                .anyRequest().authenticated() // Todas las demás requieren autenticación
            )
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
