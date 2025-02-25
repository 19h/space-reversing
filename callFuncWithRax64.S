; MASM or ml64 syntax
PUBLIC callFuncWithRaxStub

.code

callFuncWithRaxStub PROC
    ; Microsoft x64 ABI: RCX holds inRax, RDX holds func
    mov  rax, rcx      ; put pointer into RAX
    mov  rcx, rax      ; or however your function needs to set up "this"
    mov  rax, rdx      ; rax <- function pointer
    call rax           ; indirect call
    ret
callFuncWithRaxStub ENDP

END
