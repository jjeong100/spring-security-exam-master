package com.example.vue.board.exam.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.vue.board.exam.entity.BoardEntity;

public interface BoardRepository extends JpaRepository<BoardEntity, Long> {
}