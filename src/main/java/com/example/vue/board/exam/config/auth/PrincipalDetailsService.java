package com.example.vue.board.exam.config.auth;

import com.example.vue.board.exam.entity.User;
import com.example.vue.board.exam.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {
    // 시큐리티 설정에서  loinProcessingUrl의 url이 호출되면
    // UserDetailService 타입으로 IoC되어 있는 구현체의 loadUserByUsername 함수를 자동으로 호출합니다.

    private final UserRepository repository;

    // 이 함수가 종료될 때 @AuthenticationPrincipal 어노테이션이 활성화 됩니다
    // 오버라이딩 하지 않아도 활성화 됨.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                                            // 파라미터 이름이 username이 아니면 제대로 매칭이 안되기 때문에
                                            // 파라미터 이름을 꼭 맞춰주세요.
                                            // 만약 파라미터 이름을 바꾸고 싶으면 securityConfig에서 usernameParameter()로 따로 셋팅 해줘야 합니다.

        Optional<User> find = repository.findByUsername(username);

        return find.map(PrincipalDetails::new).orElse(null);
        // 여기서 return을 하게 되면 security의 session 안의 Authentication 안에 쏙 들어가게 됩니다.
        // 즉, 여기서 return을 하게 되면 userdetail로 authentication 객체 안에 들어가게 되고
        // authentication 객체는 security session 안에 들어가게 됩니다.
    }

}
