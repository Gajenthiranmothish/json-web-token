package com.gajenthiranmothish.jsonwebtoken.repo;

import com.gajenthiranmothish.jsonwebtoken.model.UserInfo;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<UserInfo, Long> {
    public UserInfo findByUsername(String username);
}
