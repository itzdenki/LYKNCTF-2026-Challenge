"""Print the Python-emulator accs for the same vectors harness.c uses."""
import struct
import asm


def words(b):
    return list(struct.unpack("<8I", b))


def run(prog, in32, target):
    return asm.vm_execute(prog, words(in32), target)


def main():
    _, inner = asm.read_flag()
    inw = words(inner.encode("latin1"))
    target = asm.arx_forward(inw)
    prog = asm.build_program()

    flag = inner.encode("latin1")
    bad = bytearray(flag); bad[5] ^= 1
    v0 = bytes(32)
    v1 = bytes([0x41]) * 32
    v2 = bytes(range(32))

    print("flag  acc = 0x%08X (expect 0)" % run(prog, flag, target))
    print("bad   acc = 0x%08X (expect != 0)" % run(prog, bytes(bad), target))
    print("v0    acc = 0x%08X" % run(prog, v0, target))
    print("v1    acc = 0x%08X" % run(prog, v1, target))
    print("v2    acc = 0x%08X" % run(prog, v2, target))


if __name__ == "__main__":
    main()
