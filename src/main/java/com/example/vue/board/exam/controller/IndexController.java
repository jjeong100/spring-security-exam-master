package com.example.vue.board.exam.controller;

import com.example.vue.board.exam.config.auth.PrincipalDetails;
import com.example.vue.board.exam.entity.User;
import com.example.vue.board.exam.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;

    @GetMapping({"", "/"})
    public String index(){
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principal){
                                    // OAuth2User, UserDetail 모두 PrincipalDetails로 구현했기 때문에 둘 다 이 타입으로 받을 수 있습니다.
        return principal.getUser().toString();
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }

    @GetMapping("/login")
    public String login(){
        return "loginForm";
    }

    @GetMapping("/loginProc")
    public @ResponseBody String loginProc(){
        return "ok";
    }

    @GetMapping("/join")
    public String join(){
        return "joinForm";
    }

    @PostMapping("/joinProc")
    public String joinProc(User user){

        user.setRole("USER");
        String encoded = passwordEncoder.encode(user.getPassword());
        user.setPassword(encoded);
        repository.save(user);
        return "redirect:/login";
    }

    @Secured("ROLE_ADMIN") // security config에서 secured 어노테이션을 활성화 했기 때문에
                        // 메서드 별로 간단하게 권한 설정을 해줄 수 있다.
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_MANAGER')") // security config에서 prePostEnabled를 활성화 시켰기 때문에 적용된다.
                                                        // 권한을 여러개로 걸고 싶을 때는 PreAuthorize를 사용하고
                                                        // 하나만 걸고 싶을 때는 secured를 사용하는 게 좋다
                                                        // 메서드가 실행되기 전에 권한을 확인한다.
    @GetMapping("/data")
//    @PostAuthorize() --> 메서드가 수행된 다음에 권한을 확인한다.
    public @ResponseBody String date(){
        return "데이터 정보";
    }

//    @GetMapping("/test/login")
//    public @ResponseBody String loginTest(Authentication authentication,
//                                          // 세션에 저장되어 있는 인증 정보를 가져옵니다
//                                          @AuthenticationPrincipal PrincipalDetails principalDetails
//                                          // Authentication에 담겨있는 사용자 정보를 꺼내줍니다.
//                                          ){
//        log.info("authentication {}", (PrincipalDetails)authentication.getPrincipal());
//        // 단 OAuth 로그인 한 사람의 정보는 PrincipalDetails 로 타입 캐스팅이 되지 않기 때문에 에러가 발생한다.
//        log.info("principalDetails {}", principalDetails);
//        return "/test/login 세션 정보 확인";
//    }

//    @GetMapping("/test/oauth/login")
//    public @ResponseBody String loginTest(Authentication authentication,
//                                        @AuthenticationPrincipal OAuth2User OAuth2User
//                                          // Authentication에 담겨있는 사용자 정보를 꺼내줍니다.
//    ){
//        OAuth2User principal = (OAuth2User) authentication.getPrincipal();
//        // 단 OAuth 로그인 한 사람의 정보는 OAuth2User 로 타입 캐스팅을 해줘야 합니다.
//        log.info("principal {}", principal.getAttributes());
//        log.info("OAuth2User {}", OAuth2User.getAttributes());
//        return "/test/oauth/login 세션 정보 확인";
//    }




}
