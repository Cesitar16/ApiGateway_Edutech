package com.gateway.jwt.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "USUARIO")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Usuario {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_user")
    private Integer idUsuario;

    @Column(name = "username")
    private String username;

    @Column(name = "email")
    private String email;

    @Column(name = "password")
    private String password;

    @Column(name = "Activo")
    private Boolean activo;

    @ManyToOne
    @JoinColumn(name = "ROL_id_rol")
    private Rol rol;
}