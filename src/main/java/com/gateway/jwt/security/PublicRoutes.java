package com.gateway.jwt.security;

public class PublicRoutes {

    // Rutas públicas para GET
    public static final String[] PUBLIC_GET = {
        "/api/ping",
        "/api/proxy/usuarios",
        "/api/proxy/usuarios/"
    };

    // Rutas públicas para POST
    public static final String[] PUBLIC_POST = {
        "/api/proxy/usuarios/login"
    };
}
