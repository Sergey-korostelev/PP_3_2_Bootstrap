package ru.kata.spring.boot_security.demo.service;

import org.springframework.stereotype.Service;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repository.UserRepository;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository dao;

    public UserServiceImpl(UserRepository dao) {
        this.dao = dao;
    }

    public Optional<User> findById(Long id) {
        return dao.findById(id);
    }

    public List<User> findAll() {
        return dao.findAll();
    }

    public void saveUser(User user) {
        dao.save(user);
    }

    public void deleteById(Long id) {
        dao.deleteById(id);
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return Optional.ofNullable(dao.findByUsername(username));
    }

    @Override
    public long count() {
        return dao.count();
    }
}
