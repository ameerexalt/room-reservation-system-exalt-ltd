package com.example.roomreservation.model.user;

import com.example.roomreservation.model.user.User;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

@Getter
@Setter
public class MyUserDetails implements UserDetails {

    private Optional<User> user;

    public MyUserDetails(Optional<User> user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String role = user.get().getRole();
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        authorities.add(new SimpleGrantedAuthority(role));

        return authorities;
    }

    @Override
    public String getPassword() {
        return user.get().getPassword();
    }

    @Override
    public String getUsername() {
        return user.get().getUsername();
    }

    public String getEmail() {
        return user.get().getEmail();
    }

    public String getRole(){
        return user.get().getRole();
    }


    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

}
