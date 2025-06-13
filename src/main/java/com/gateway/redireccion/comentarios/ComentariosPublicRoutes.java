package com.gateway.redireccion.comentarios;

public class ComentariosPublicRoutes {

    public static final String[] COMENTARIOS_PUBLIC_GET = {
        "/api/proxy/comentarios",
        "/api/proxy/comentarios/",
        "/api/proxy/comentarios/curso/{cursoId}",
        "/api/proxy/comentarios/usuario/{usuarioId}"
    };

    public static final String[] COMENTARIOS_PUBLIC_POST = {
        "/api/proxy/comentarios/crear"
    };
}