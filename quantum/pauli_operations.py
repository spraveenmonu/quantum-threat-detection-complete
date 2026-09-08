CORRECTIONS = {
    "00": "I",
    "01": "X",
    "10": "Z",
    "11": "XZ"
}

def correction_for_bits(bits):
    return CORRECTIONS.get(bits, "I")
