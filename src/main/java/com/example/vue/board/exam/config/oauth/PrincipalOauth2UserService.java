package com.example.vue.board.exam.config.oauth;

import com.example.vue.board.exam.config.auth.PrincipalDetails;
import com.example.vue.board.exam.entity.User;
import com.example.vue.board.exam.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;


    // oauth2 로그인 후 후처리를 해줍니다.
    // 구글로부터 받은 userRequest 데이터에 대한 후처리를 해주는 함수
    // 무슨 정보가 있냐면... -> 액세스토큰, 사용자 정보

    // 이 함수가 종료될 때 @AuthenticationPrincipal 어노테이션이 활성화 됩니다
    // 오버라이딩 하지 않아도 활성화 됨.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);// 이 함수를 타면 사용자 정보가 로드 됩니다.
        // 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인을 완료 -> 로그인 code를 리턴 -> access token 리턴  <<-- OAuth2UserRequest
        // access token으로 사용자 정보 요청 -> 사용자 정보 리턴 받음 <<-- super.loadUser(userRequest)

        String username = userRequest.getClientRegistration().getClientId() + oAuth2User.getName();
        Optional<User> find = repository.findByUsername(username);

        if(find.isPresent()){
            return new PrincipalDetails(find.get(), oAuth2User.getAttributes());
        }else{
            User user = new User()
                    .setUsername(username)
                    .setPassword(passwordEncoder.encode("getInThere"))
                    .setRole("ROLE_USER")
                    .setProvider(userRequest.getClientRegistration().getClientId())
                    .setProviderId(oAuth2User.getAttribute("sub"))
                    .setEmail(oAuth2User.getAttribute("email"));
            User persist = repository.save(user);
            return new PrincipalDetails(persist, oAuth2User.getAttributes());
        }
    }
}
