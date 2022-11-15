package com.study.domain.member;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class MemberDto {
	private String id;
	private String nickName;
	private String password;
	private String email;
	
	private LocalDateTime inserted;
}
