package com.gateway.jwt.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.micrometer.common.lang.NonNull;

import java.io.IOException;

// Importa tus clases de rutas públicas
import com.gateway.redireccion.roles.RolesPublicRoutes;
import com.gateway.redireccion.usuarios.UsuariosPublicRoutes;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter  {

    private final JwtUtil jwtUtil;
    private final UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();

        System.out.println("➡️ PATH: " + path);

        // 1. Validar rutas públicas GET para Roles
        if ("GET".equalsIgnoreCase(method)) {
            for (String route : RolesPublicRoutes.ROLES_PUBLIC_GET) {
                if (matchesRoute(path, route)) {
                    filterChain.doFilter(request, response);
                    return; // Salimos sin validar token
                }
            }

            // Validar rutas públicas GET para Usuarios
            for (String route : UsuariosPublicRoutes.USUARIOS_PUBLIC_GET) {
                if (matchesRoute(path, route)) {
                    filterChain.doFilter(request, response);
                    return;
                }
            }
            // También validar rutas tipo /api/proxy/usuarios/{id} para usuarios
            for (String route : UsuariosPublicRoutes.USUARIOS_PUBLIC_GET_BY_ID) {
                String baseRoute = route.replace("/{id}", "");
                if (path.startsWith(baseRoute)) {
                    filterChain.doFilter(request, response);
                    return;
                }
            }
        }

        // 2. Validar rutas públicas POST (independientemente del método anterior)
        if ("POST".equalsIgnoreCase(method)) {
            for (String route : PublicRoutes.PUBLIC_POST) {
                if (matchesRoute(path, route)) {
                    filterChain.doFilter(request, response);
                    return;
                }
            }
        }

        // 3. Validación JWT normal para otras rutas
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (jwtUtil.validateToken(token)) {
                String username = jwtUtil.extractUsername(token);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        } else {
            // Aquí podrías decidir si quieres bloquear o dejar pasar peticiones sin token
            // Por ejemplo: si la ruta no es pública y no tiene token, devolver 403 o 401
            // Pero si quieres que se bloqueen automáticamente, puedes lanzar excepción aquí
        }

        filterChain.doFilter(request, response);
    }

    // Método helper para comparar rutas exactas o con "/" al final
    private boolean matchesRoute(String path, String route) {
        return path.equals(route) || path.equals(route + "/");
    }

}
