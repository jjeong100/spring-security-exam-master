package com.example.vue.board.exam;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class SpringSecurityExamApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityExamApplication.class, args);
    }

}
