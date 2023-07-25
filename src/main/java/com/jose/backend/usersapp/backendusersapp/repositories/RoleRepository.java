package com.jose.backend.usersapp.backendusersapp.repositories;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.jose.backend.usersapp.backendusersapp.models.entities.Role;


public interface RoleRepository
  extends CrudRepository<Role, Long>{
 
  Optional<Role> findByname(String name); 


}
