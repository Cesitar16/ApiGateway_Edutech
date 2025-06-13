package com.gateway.redireccion.comentarios;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import com.gateway.jwt.service.JwtService;

@RestController
@RequestMapping("/api/proxy/comentarios")
@RequiredArgsConstructor
public class ComentariosProxyController {

    private final RestTemplate restTemplate;
    private final JwtService jwtService;

    @RequestMapping(value = "/**", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE})
    public ResponseEntity<?> proxyComentarios(HttpServletRequest request,
                                              @RequestBody(required = false) String body,
                                              @RequestHeader HttpHeaders headers) {

        String originalPath = request.getRequestURI().replace("/api/proxy/comentarios", "");
        String targetUrl = "http://localhost:8008/api/comentarios" + originalPath;
        HttpMethod method = HttpMethod.valueOf(request.getMethod());

        // Validar DELETE solo para admins
        if (method == HttpMethod.DELETE) {
            String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\": \"Token no presente o inválido\"}");
            }

            String token = authHeader.replace("Bearer ", "");
            String rol = jwtService.extractClaim(token, claims -> claims.get("rol", String.class));

            if (!"Administrador".equalsIgnoreCase(rol)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\": \"Solo admin puede eliminar comentarios\"}");
            }
        }

        // Clonar headers válidos
        HttpHeaders cleanHeaders = new HttpHeaders();
        headers.forEach((key, value) -> {
            if (!key.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)) {
                cleanHeaders.put(key, value);
            }
        });
        cleanHeaders.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> entity = new HttpEntity<>(body, cleanHeaders);

        // Capturar errores para mantener respuestas en JSON
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
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Error inesperado en el API Gateway\", \"detalle\": \"" + ex.getMessage() + "\"}");
        }
    }
}