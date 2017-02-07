; Functions taken from ntdll.dll bundled in Windows 10 15025, so they are copyright of Microsoft
;
; Functions are needed once you allocate something on stack
; TODO: exception handling

.code

public __security_check_cookie_ex
public __security_check_cookie_ex_sp

extern __security_cookie:qword
extern __report_gsfailure:proc
extern __guard_ss_verify_sp:proc

__security_check_cookie_ex proc
	mov     r8, [rsp+0]
	cmp     rcx, __security_cookie
	jnz     report_gsfailure
	rol     rcx, 10h
	test    cx, 0FFFFh
	jnz     restore_cookie
	nop
	cmp     r8, [rsp+0]
	jnz     report_fast_fail
	ret
restore_cookie:
	ror     rcx, 10h
report_gsfailure:
	jmp     __report_gsfailure
report_fast_fail:
	mov     rdx, [rsp+0]
	mov     ecx, 2Ch
	int     29h
__security_check_cookie_ex endp

__security_check_cookie_ex_sp proc
	mov     r8, [rsp+0]
	cmp     rcx, __security_cookie
	jnz     report_gsfailure
	rol     rcx, 10h
	test    cx, 0FFFFh
	jnz     restore_cookie
	nop
	mov     rcx, rdx
	cmp     r8, [rsp+0]
	jnz     report_fast_fail
	jmp     __guard_ss_verify_sp
restore_cookie:
	ror     rcx, 10h
report_gsfailure:
	jmp     __report_gsfailure
report_fast_fail:
	mov     rdx, [rsp+0]
	mov     ecx, 2Ch
	int     29h
__security_check_cookie_ex_sp endp

end
