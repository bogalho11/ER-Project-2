from qiling import *
from qiling.const import QL_INTERCEPT

# the  qiling base addr is 0x555555559900
# from ghidra addr to qiling addr
def ADDR_GH(addr: int):
    return 0x555555454000 + addr

# from binary ninja addr to qiling addr
def ADDR_BN(addr: int):
    return 0x555555554000 + addr

def my_pow(ql: Qiling):
    params = ql.os.resolve_fcall_params({'x': float, 'y': float})
    ql.arch.regs.xmm0 = pow(params['x'], params['y'])

def detect_debugger_decrypt_hook(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in detect_debugger(): {result}")

    # go to the detect_qiling() decrypt() call
    ql.arch.regs.rip = ADDR_BN(0x00005f62)

def detect_qiling_decrypt_hook1(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in detect_qiling(): {result}")

    # go to the second detect_qiling() decrypt() call
    ql.arch.regs.rip = ADDR_BN(0x00005fb9)
 
def detect_qiling_decrypt_hook2(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in detect_qiling(): {result}")

    # go to the detect_vm() decrypt() call
    ql.arch.regs.rip = ADDR_BN(0x00005d30)

def detect_vm_decrypt_hook1(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in detect_vm(): {result}")

    # go to the second detect_vm() decrypt() call
    ql.arch.regs.rip = ADDR_BN(0x00005d87)

def detect_vm_decrypt_hook2(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in detect_vm(): {result}")

    # go to the ramsomware() decrypt() call
    ql.arch.regs.rip = ADDR_BN(0x0000614d)

def ramsomware_decrypt_hook(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in ramsomware(): {result}")

    # go to the install_program_to_crontab() decrypt() call
    ql.arch.regs.rip = ADDR_BN(0x000064c7)

def install_program_to_crontab_decrypt_hook1(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in install_program_to_crontab(): {result}")

    # go to the second install_program_to_crontab() decrypt() call
    ql.arch.regs.rip = ADDR_BN(0x000065ae)

def install_program_to_crontab_decrypt_hook2(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in install_program_to_crontab(): {result}")

    # go to the third install_program_to_crontab() decrypt() call
    ql.arch.regs.rip = ADDR_BN(0x00006659)

def install_program_to_crontab_decrypt_hook3(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in install_program_to_crontab(): {result}")

    # go to the fourth install_program_to_crontab() decrypt() call
    ql.arch.regs.rip = ADDR_BN(0x000066a6)

def install_program_to_crontab_decrypt_hook4(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in install_program_to_crontab(): {result}")

    # go to the main() decrypt() call
    ql.arch.regs.rip = ADDR_BN(0x000067e8)

def main_hook1(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in main(): {result}")

    # go to the second main() decrypt() call
    ql.arch.regs.rip = ADDR_BN(0x00006836)

def main_hook2(ql: Qiling):
    result = ql.mem.read(ql.arch.regs.rax, 1024).split(b'\x00')[0].decode()
    print(f"Decrypted string in main(): {result}")
    ql.stop()

def sandbox(path: list[str], rootfs: str):
    ql = Qiling(path, rootfs)

    # intercept calls to pow()
    ql.os.set_api('pow', my_pow, QL_INTERCEPT.CALL)

    ql.hook_address(detect_debugger_decrypt_hook, ADDR_BN(0x00005eb6))             # detect_debugger()
    ql.hook_address(detect_qiling_decrypt_hook1, ADDR_BN(0x00005f76))              # detect_qiling()
    ql.hook_address(detect_qiling_decrypt_hook2, ADDR_BN(0x00005fcd))              # detect_qiling()
    ql.hook_address(detect_vm_decrypt_hook1, ADDR_BN(0x00005d44))                  # detect_vm()
    ql.hook_address(detect_vm_decrypt_hook2, ADDR_BN(0x00005d9b))                  # detect_vm()
    ql.hook_address(ramsomware_decrypt_hook, ADDR_BN(0x00006161))                  # ramsomware()
    ql.hook_address(install_program_to_crontab_decrypt_hook1, ADDR_BN(0x000064db)) # install_program_to_crontab()
    ql.hook_address(install_program_to_crontab_decrypt_hook2, ADDR_BN(0x000065c2)) # install_program_to_crontab()
    ql.hook_address(install_program_to_crontab_decrypt_hook3, ADDR_BN(0x0000666d)) # install_program_to_crontab()
    ql.hook_address(install_program_to_crontab_decrypt_hook4, ADDR_BN(0x000066ba)) # install_program_to_crontab()
    ql.hook_address(main_hook1, ADDR_BN(0x000067f0))                               # main()
    ql.hook_address(main_hook2, ADDR_BN(0x0000684a))                               # main()

    # start the chain of decrypt calls
    ql.run(begin=ADDR_BN(0x00005ea2))

if __name__ == '__main__':
    sandbox(['./game'], 'rootfs')
