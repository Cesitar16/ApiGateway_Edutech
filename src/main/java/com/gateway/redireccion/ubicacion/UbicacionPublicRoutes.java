package com.gateway.redireccion.ubicacion;

public class UbicacionPublicRoutes {

    public static final String[] UBICACION_PUBLIC_GET = {
        "/api/proxy/ubicacion/comunas",
        "/api/proxy/ubicacion/comunas/{id}",
        "/api/proxy/ubicacion/provincias",
        "/api/proxy/ubicacion/provincias/{id}"
    };

    public static final String[] UBICACION_PUBLIC_POST = {
        "/api/proxy/ubicacion/comunas/crear",
        "/api/proxy/ubicacion/provincias/crear"
    };
}