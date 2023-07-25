package com.jose.backend.usersapp.backendusersapp.services;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.jose.backend.usersapp.backendusersapp.models.dto.UserDto;
import com.jose.backend.usersapp.backendusersapp.models.entities.User;
import com.jose.backend.usersapp.backendusersapp.models.request.UserRequest;

public interface UserService {

  List<UserDto> findAll();

  Page<UserDto> findAll(Pageable pageable);
  
  Optional<UserDto> finById(Long id);

  UserDto save(User user);

  Optional <UserDto> update(UserRequest user, Long id);
  
  void remove(Long id);

  
  
}
