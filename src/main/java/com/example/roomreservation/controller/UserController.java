package com.example.roomreservation.controller;

import com.example.roomreservation.model.user.User;
import com.example.roomreservation.model.user.UserDTO;
import com.example.roomreservation.service.UserDetailsServiceImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserDetailsServiceImpl userService;

    public UserController(UserDetailsServiceImpl userService) {
        this.userService = userService;
    }

    @GetMapping("/all")
    public ResponseEntity<List<User>> getAllUsers(){
        List<User> userList= userService.getAllUsers();
        return new ResponseEntity<>(userList, HttpStatus.OK);
    }

    //get a user by its username
    @GetMapping
    public ResponseEntity<User> getUserByUsername(@RequestParam String username){
        User user= userService.loadUserByUsername(username).getUser().get();
        return new ResponseEntity<>(user, HttpStatus.OK);
    }
    // create a new user

    @PostMapping("/addUser")
    public ResponseEntity<User> add(@RequestBody User user) throws Exception{
        User addedUser = userService.addUser(user);
        return new ResponseEntity<>(addedUser, HttpStatus.CREATED);
    }

    @PutMapping("/{userName}")
    public ResponseEntity<User> update(@RequestBody @Valid UserDTO user, @PathVariable String userName) throws Exception{
        User updatedUser = userService.updateUser(user);
        return new ResponseEntity<>(updatedUser, HttpStatus.CREATED);
    }

    @DeleteMapping("/{userName}")
    public ResponseEntity<String> delete(@PathVariable String userName){
        String message = userService.deleteUser(userName);
        return new ResponseEntity<>(message, HttpStatus.OK);
    }

}
