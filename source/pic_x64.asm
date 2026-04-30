.code

extern PicHandler:proc

CallbackThunk proc
        ; Save all argument registers. This is not needed for syscall thunks, but
        ; instrumented callbacks are used for all transitions from kernel to user mode,
        ; not just syscalls. APCs, thread start routines, and other transitions may
        ; expect all argument registers to be valid by the target routine. As such, we
        ; have to save and restore them. Not doing so or explicitly modifying them can
        ; cause an exception. An example is if ntdll calls NtReleaseWorkerFactoryWorker
        ; while LoadLibrary is running. That will call LdrInitializeThunk which expects
        ; rcx and rdx to be valid arguments. If we modify those to something the thunk
        ; can not use, then the thunk will call RtlRaiseStatus.
        ;
        ; It was also observed during debugging that exceptions can be thrown when r10
        ; is not saved. The root cause of this was not evaluated. To be safe, all
        ; volatile registers saved to prevent their modification from throwing an
        ; exception. This includes argument registers, r10, and r11. Rax is also volatile,
        ; but it can be saved or modified as needed by PicHandler.
        push r11
        push r10
        push r9
        push r8
        push rdx
        push rcx

        ; Nonvolatile registers the thunk modifies must also be saved. These include:
        ; - rbx, rbp, rdi, rsi, rsp, r12, r13, r14, and r15.
        ; The thunk currently only modifies rsi. 
		push rsi

    thunk_body:
        ; Return early if InstrumentationCallbackDisabled is set to prevent recursion
        mov rdx, gs:[2ech] ; rcx = TEB.InstrumentationCallbackDisabled
        test rdx, rdx
        jnz epilogue

        ; Set InstrumentationCallbackDisabled
        mov cl, 1
		mov gs:[2ech], rdx ; TEB.InstrumentationCallbackDisabled = 1 (true)

        ; Set up the arguments for PicHandler
        mov rcx, r10       ; arg1 = original return address
        lea rdx, [rsp+38h] ; arg2 = original stack value
        mov r8, rax        ; arg3 = original return value
        
        ; Call PicHandler
        mov  rsi, rsp      ; Save the value of rsp so it can be restored after the call
        sub  rsp, 100      ; Allocate homing space (note: this is more than needed)
        and  rsp, -10h     ; Align rsp to 16 bytes for SSE instructions to not throw
        call PicHandler    ; Call the C++ handler
        mov  rsp, rsi      ; Restore the original value of rsp
        
        ; Unset InstrumentationCallbackDisabled
        xor rdx, rdx
		mov gs:[2ech], rdx ; TEB.InstrumentationCallbackDisabled = 0 (false)

    epilogue:
        ; Restore nonvolatile registers that were saved
        pop rsi

        ; Restore all volatile registers
        pop rcx
        pop rdx
        pop r8
        pop r9
        pop r10
        pop r11

        ; Jump to the original return address. This will be a syscall, APC,
        ; thread start routine, or any other kernel to user mode transition.
        jmp r10
CallbackThunk endp

end