package com.gateway.redireccion.roles;

public class RolesPublicRoutes {

    // Rutas públicas accesibles con método GET para roles
    public static final String[] ROLES_PUBLIC_GET = {
        "/api/proxy/roles",        // listar todos los roles
        "/api/proxy/roles/",       // para evitar problemas con slash final
        "/api/proxy/roles/*"       // obtener rol por id (ej: /api/proxy/roles/1)
    };

}
