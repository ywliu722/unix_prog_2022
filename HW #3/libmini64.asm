
%macro gensys 2
	global sys_%2:function
sys_%2:
	push	r10
	mov	r10, rcx
	mov	rax, %1
	syscall
	pop	r10
	ret
%endmacro

; RDI, RSI, RDX, RCX, R8, R9

extern	errno

	section .data

	section .text

	gensys   1, write
	gensys  34, pause
	gensys  35, nanosleep
    gensys  37, alarm
	gensys  60, exit

    gensys  13, rt_sigaction
    gensys  14, rt_sigprocmask
    gensys  127, rt_sigpending

	global setjmp:function
setjmp:
    ; store the registers to jmp_buf
    mov [rdi + 8 * 0], rbx
    mov [rdi + 8 * 1], rsp
    mov [rdi + 8 * 2], rbp
    mov [rdi + 8 * 3], r12
    mov [rdi + 8 * 4], r13
    mov [rdi + 8 * 5], r14
    mov [rdi + 8 * 6], r15

    ; store the return address of the caller
    push qword [rsp]
    pop qword [rdi + 8 * 7]

    ; push register to stack in order to call the syscall
    push rdi
    push rsi
    push rdx
    push rcx

    ; sys_rt_sigprocmask(int how, sigset_t *nset, sigset_t *oset, size_t sigsetsize)
	; (rdi, rsi, rdx, rcx)
    mov rdi, 0
    mov rsi, 0
    lea rdx, [rdi + 8 * 8] ; mem address of jmp_buf->mask
    mov rcx, 8  ; NSIG/8 = 8

    call sys_rt_sigprocmask

    ; retrive the value of register
    pop rcx
    pop rdx
    pop rsi
    pop rdi

    mov rax, 0  ; return value of setjmp
    ret

    global longjmp:function
longjmp:
    ; pop the return address that no longer used
    pop rax

    ; restore the registers
    mov rbx, [rdi + 8 * 0]
    mov rsp, [rdi + 8 * 1]
    mov rbp, [rdi + 8 * 2]
    mov r12, [rdi + 8 * 3]
    mov r13, [rdi + 8 * 4]
    mov r14, [rdi + 8 * 5]
    mov r15, [rdi + 8 * 6]
    ; push the return address of the caller to stack
    push qword [rdi + 8 * 7]

    ; push register to stack in order to call the syscall
    push rdi
    push rsi
    push rdx
    push rcx

    ; sys_rt_sigprocmask(int how, sigset_t *nset, sigset_t *oset, size_t sigsetsize)
	; (rdi, rsi, rdx, rcx)
    mov rdi, 2  ; SIG_SETMASK
    lea rsi, [rdi + 8 * 8] ; mem address of jmp_buf->mask
    mov rdx, 0
    mov rcx, 8  ; NSIG/8 = 8

    call sys_rt_sigprocmask

    ; retrive the value of register
    pop rcx
    pop rdx
    pop rsi
    pop rdi

    ; if val = 0, replace it with 1
    cmp rsi, 0
    jne longjmp_ret ; val != 0
    inc rsi ; set return value to 1
longjmp_ret:
    mov rax, rsi
    ret

    global myrt:function
myrt:
        mov rax, 15
        syscall
        ret
