import struct

def encode_ordinal(ordinal):
    enc = []
    enc.append(ordinal&0x7f|0x40)
    if ordinal > 0x3f:
        bt = ordinal
        bt = bt // 0x40
        enc.append(bt&0x7f|0x80)
        while bt > 0x7f:
            bt = bt // 0x80
            enc.append(bt&0x7f|0x80)
    stemp = ""
    for i in range(0,len(enc)):
        stemp = stemp + struct.pack("B",enc.pop(-1))
    return stemp
        


def decode_ordinal(enc):
    ord_num = 0
    i = 0
    fEnd = 0
    len = struct.unpack("B",enc[0])
    for ch in enc:
        ch = ord(ch)
        if ch == 0:
            return 0
        ord_num = ord_num * 0x40
        if ch&0x80 != 0:
            ord_num = ord_num * 2
            ch = ch & 0x7f
        else:
            ch = ch & 0x3f
            fEnd = 1
        ord_num = ord_num | ch
        if fEnd > 0 or i >= len:
            break
    return ord_num
        
        
print decode_ordinal('\x81\x80')
temp = ''
print encode_ordinal(13055).encode("hex")
print encode_ordinal(0x200).encode("hex")
