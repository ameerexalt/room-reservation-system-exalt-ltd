package com.example.roomreservation.service;

import com.example.roomreservation.model.token.TokenInfo;
import com.example.roomreservation.repository.TokenInfoRepository;
import com.example.roomreservation.security.JwtTokenUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenInfoService {

    private final TokenInfoRepository tokenInfoRepository;
    private final JwtTokenUtils jwtTokenUtils;

    public TokenInfo findById(Long id){
        return tokenInfoRepository.findById(id).orElse(null);
    }

    public Optional<TokenInfo> findByRefreshToken(String refreshToken){
        return tokenInfoRepository.findByRefreshToken(refreshToken);
    }

    public TokenInfo saveToken(TokenInfo tokenInfo){
        return tokenInfoRepository.save(tokenInfo);
    }


    public void deleteById(Long id) {
        tokenInfoRepository.deleteById(id);
        log.info(String.format("the token with id: %s is deleted"));
    }

    public TokenInfo verifyExpiration(TokenInfo token) {
        if (jwtTokenUtils.isTokenExpired(token.getRefreshToken())) {
            tokenInfoRepository.delete(token);
            throw new RuntimeException("Refresh token was expired. Please make a new signin request");
        }

        return token;
    }

}
