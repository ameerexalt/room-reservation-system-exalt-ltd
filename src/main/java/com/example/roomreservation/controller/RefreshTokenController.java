package com.example.roomreservation.controller;

import com.example.roomreservation.model.token.TokenInfo;
import com.example.roomreservation.model.user.User;
import com.example.roomreservation.security.JwtTokenUtils;
import com.example.roomreservation.service.TokenInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/v1/refreshAccessToken")
public class RefreshTokenController {

    private final  TokenInfoService tokenInfoService;

    @Autowired
    public RefreshTokenController(TokenInfoService tokenInfoService){
        this.tokenInfoService = tokenInfoService;
    }
    @PostMapping
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenInfo request) {
        String requestRefreshToken = request.getRefreshToken();

        return tokenInfoService.findByRefreshToken(requestRefreshToken)
                .map(tokenInfoService::verifyExpiration)
                .map(TokenInfo:: getUser )
                .map(user -> {
                    String token = JwtTokenUtils.generateToken(((User) user).getUsername(),((User) user).getRole(),request.getAccessToken(),false);

                    return ResponseEntity.ok(new TokenInfo(token, requestRefreshToken));
                })
                .orElseThrow(() -> new RuntimeException("Refresh token is not in database!"));
    }
}

