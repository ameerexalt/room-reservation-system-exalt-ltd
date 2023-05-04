package com.example.roomreservation.service;

import com.example.roomreservation.exception.user.UserNotFoundException;
import com.example.roomreservation.model.user.User;
import com.example.roomreservation.model.user.UserDTO;
import com.example.roomreservation.repository.UserRepository;
import com.example.roomreservation.model.user.MyUserDetails;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    private final ModelMapper modelMapper;
    @Autowired
    public UserDetailsServiceImpl( ModelMapper modelMapper) {
        this.modelMapper = modelMapper;
    }
    @Override
    public MyUserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {
        Optional<User> user = userRepository.findUserByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("Could not find user");
        }

        return new MyUserDetails(user);
    }

    public List<User> getAllUsers(){
        List<User>users= userRepository.findAll();
        if (users.isEmpty()){
            throw new UserNotFoundException("There is no Users in the System");
        }
        return users;
    }

    public Boolean isPresentUsername(String username) {
        Optional<User> myuser = userRepository.findUserByUsername(username);
        if (!myuser.isPresent()){
            return false;
        }return true;
    }

    public User addUser(User user) {
        User newUser =modelMapper.map(user,User.class);
        String password = newUser.getPassword();
        newUser.setPassword(new BCryptPasswordEncoder().encode(password));
        newUser= userRepository.save(newUser);
        return newUser;
    }

    public User updateUser(UserDTO updatedUser) {
        User actualUser = userRepository.findUserByUsername(updatedUser.getUsername())
                .orElseThrow(() -> new UserNotFoundException("User not found with username: " + updatedUser.getUsername()));
        modelMapper.map(updatedUser,actualUser);
        return userRepository.save(actualUser);
    }

    public String deleteUser(String userName) {
        loadUserByUsername(userName);
        String message =String.format("User with the username %s is deleted",userName);
        userRepository.deleteById(userName);
        return message;
    }

}