package com.gateway.jwt.repository;

import com.gateway.jwt.model.Rol;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RolRepository extends JpaRepository<Rol, Integer> {
    
}