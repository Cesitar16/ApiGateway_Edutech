package com.gateway.redireccion.usuarios;

import com.gateway.jwt.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/proxy/usuarios")
@RequiredArgsConstructor
public class UsuariosProxyController {

    private final RestTemplate restTemplate;
    private final JwtService jwtService;

    @RequestMapping(value = "/**", method = {
            RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE})
    public ResponseEntity<?> proxyUsuarios(HttpServletRequest request,
                                           @RequestBody(required = false) String body,
                                           @RequestHeader HttpHeaders headers) {

        String originalPath = request.getRequestURI().replace("/api/proxy/usuarios", "");
        String targetUrl = "http://localhost:8003/api/usuarios" + originalPath;
        HttpMethod method = HttpMethod.valueOf(request.getMethod());

        // Validar métodos sensibles
        if (method != HttpMethod.GET) {
            String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\": \"Token no presente o inválido\"}");
            }

            String token = authHeader.replace("Bearer ", "");
            try {
                jwtService.extractUsername(token); // Solo valida si el token es válido
            } catch (Exception ex) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\": \"Token inválido\"}");
            }
        }

        // Limpiar headers antes de reenviar
        HttpHeaders cleanHeaders = new HttpHeaders();
        headers.forEach((key, value) -> {
            if (!key.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)) {
                cleanHeaders.put(key, value);
            }
        });
        cleanHeaders.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> entity = new HttpEntity<>(body, cleanHeaders);

        try {
            ResponseEntity<String> response = restTemplate.exchange(targetUrl, method, entity, String.class);
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(response.getBody());

        } catch (HttpClientErrorException | HttpServerErrorException ex) {
            return ResponseEntity.status(ex.getStatusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(ex.getResponseBodyAsString());

        } catch (Exception ex) {
            // Aquí imprimimos el stack trace para ver el error completo en consola
            ex.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Error inesperado en el API Gateway\", \"detalle\": \"" + ex.getMessage() + "\"}");
        }
    }
}
