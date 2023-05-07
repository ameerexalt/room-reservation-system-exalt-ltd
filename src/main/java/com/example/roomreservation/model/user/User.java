package com.example.roomreservation.model.user;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Entity
@Table
@Data
@ToString
@NoArgsConstructor
public class  User {

    @NotBlank
    @Id
    @Column(length = 100)
    private String username;

    @NotBlank
    @Size(max = 50)
    private String email;

    @NotBlank
    @Size(max = 50)
    private String role;

    @NotBlank
    @Size(max = 50)
    private String password;


    public User(String username, String email, SimpleGrantedAuthority role, String password) {
        this.username = username;
        this.email=email;
        this.role = role.getAuthority();
        this.password = password;
    }

}
