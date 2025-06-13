package com.gateway.redireccion.cursos;

public class CursosPublicRoutes {

    public static final String[] CURSOS_PUBLIC_GET = {
        "/api/proxy/cursos/cursos",
        "/api/proxy/cursos/cursos/",
        "/api/proxy/cursos/cursos/{id}",
        "/api/proxy/cursos/categorias",
        "/api/proxy/cursos/categorias/",
        "/api/proxy/cursos/categorias/{id}",
        "/api/proxy/cursos/categorias/{categoriaId}/cursos",
        "/api/proxy/cursos/modulos",
        "/api/proxy/cursos/modulos/",
        "/api/proxy/cursos/modulos/{id}",
        "/api/proxy/cursos/modulos/{moduloId}/contenidos",
        "/api/proxy/cursos/contenidos",
        "/api/proxy/cursos/contenidos/",
        "/api/proxy/cursos/contenidos/{id}"
    };

    public static final String[] CURSOS_PUBLIC_POST = {
        // Si permites registros abiertos, podrías incluir alguno aquí
        // Por ejemplo: "/api/proxy/cursos/cursos/crear"
    };
}