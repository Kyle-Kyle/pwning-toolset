from pwn import *
import numpy as np
import scipy.cluster.hierarchy as hcluster

KERNEL_BIN = "./vmlinuz"
ROOTFS = "./rootfs.img"
KERNEL_ELF = "./vmlinux"

elf = ELF(KERNEL_ELF)

gadgets = []

def launch():
    log.info("Launching QEMU...")
    cmd = ['qemu-system-x86_64', '-m', '1G', '-cpu', 'host', '--enable-kvm', '-initrd', ROOTFS, '-kernel', KERNEL_BIN, '-nographic', '-monitor', '/dev/null', '-append', '"console=ttyS0 kaslr quiet panic=1"']
    r = process(cmd)
    output = r.recvregex(b"/ (\$|#) ", timeout=10)
    prompt = output.splitlines()[-1]
    assert b'#' in prompt, "you must be root to use this script!"
    return r

def parse_kallsyms(r):
    log.info("Trying to grab and parse kallsyms...")

    # grab raw kallsyms output first
    r.sendline(b"cat /proc/kallsyms")
    output = r.recvuntil(b"#")

    # grab kernel text entries
    entries = [x.split() for x in output.splitlines() if len(x.split()) == 3]
    text_entries = [x for x in entries if x[1].lower() == b't']

    # calculate function offsets
    base = [x for x in text_entries if x[2] == b'_stext'][0][0]
    base = int(base, 16)
    d = {x[2]: int(x[0], 16)-base for x in text_entries}

    return d

def get_fresh_offsets():
    r = launch()
    sym = parse_kallsyms(r)
    r.close()
    return sym

def get_func_size():
    log.info("Trying to grab function size...")
    d = {}
    for x in elf.sections:
        if not x.name.startswith(".text."):
            continue
        func_size = len(x.data())
        func_name = x.name[6:]
        d[func_name] = func_size
    return d

def get_invariant_func_offsets():
    log.info("Trying to identify invariant function offsets")
    off1 = get_fresh_offsets()
    off2 = get_fresh_offsets()
    off3 = get_fresh_offsets()
    
    offsets = {x:off1[x] for x in off1 if x in off1 and x in off2 and x in off3 and off1[x] == off2[x] and off2[x] == off3[x]}

    # be careful, we only grab functions from .text section, not .init stuff
    offsets = {x:offsets[x] for x in offsets if offsets[x] < 0xc00000}

    log.success(f"Identified {len(offsets)} invariant functions!")
    return offsets

def virt_to_phys(offset):
    return elf.vaddr_to_offset(elf.address+offset)

def do_gadget_search(min_offset, max_offset):
    """
    translate virtual address and file offset back and forth so that fking ROPgadget won't eat up the memory of my computer
    """
    min_phys_off = virt_to_phys(min_offset)
    max_phys_off = virt_to_phys(max_offset)

    cmd = b"ROPgadget --binary ./vmlinux --rawArch=x86 --rawMode=64 --range %#x-%#x" % (min_phys_off, max_phys_off)
    output = subprocess.getoutput(cmd)

    for line in output.splitlines():
        if not line.startswith("0x"):
            continue
        elem = line.split(' : ')
        phys_off = int(elem[0], 16)
        vaddr = elf.offset_to_vaddr(phys_off)

        gadgets.append((vaddr, elem[1]))

def clean_gadgets():
    # de-duplicate gadgets
    seen = set()
    new_gadgets = []
    for gadget in gadgets:
        if gadget[1] in seen:
            continue
        new_gadgets.append(gadget)
        seen.add(gadget[1])

    # sort gadgets
    new_gadgets.sort(key = lambda x: x[1])
    return new_gadgets

def show_gadgets():
    for gadget in gadgets:
        line = "%#x : %s" % (gadget[0], gadget[1])
        print(line)
        
size_dict = get_func_size()
offset_dict = get_invariant_func_offsets()

data = np.array(list(offset_dict.values()))
data = data.reshape(data.shape[0], 1)
clusters = hcluster.fclusterdata(data, 0x200, criterion="distance")

for cid in range(1, clusters.max()+1):
    region = data[clusters == cid]
    do_gadget_search(int(region.min()), int(region.max()))

gadgets = clean_gadgets()
show_gadgets()
