package com.example.vue.board.exam.entity;

import java.time.Instant;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

@Entity
@Getter @Setter
@ToString
@EntityListeners(AuditingEntityListener.class)
@Accessors(chain = true)
@Table(name="\"USER\"")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String username;
    private String password;
    private String email;
    private String role;

    private String provider; // 소셜로그인 시 어느 sns를 사용했는지
    private String providerId; // 소셜로그인 시 해당 sns의 id

    @CreatedDate
    private Instant createdAt;

}
