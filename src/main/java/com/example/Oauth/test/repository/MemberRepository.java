package com.example.Oauth.test.repository;

import com.example.Oauth.test.model.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {
    public Member findByUsername(String username);
}
