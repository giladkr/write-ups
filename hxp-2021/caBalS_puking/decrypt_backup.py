from pathlib import Path

def get_frame(data: bytes):
    if data.startswith(b'\x00\x00'):
        size = int.from_bytes(data[:4], 'big') + 4
        return size, data[4:size-10]
    else:
        size = data.find(b'\x00\x00')
        # making sure its not a random \x00\x00
        while size + 4 + int.from_bytes(data[size:size+4], 'big') != data.find(b'\x00\x00', size+4):
            size = data.find(b'\x00\x00', size+4)
        return size, data[:size-10]

def extract_frames(backup_data: bytes):
    frames = []
    while backup_data:
        size, block = get_frame(backup_data)
        backup_data = backup_data[size:]
        frames.append(block)
    return frames[1:] # return frames (without the header)

def xor(a, b):
    return bytes(aa ^ bb for aa, bb in zip(a, b))

# previously generated using signal-backup-exporter
my_backup_decrypted_frames = eval(Path('my_backup_frames').read_text())
empty_encrypted_frames = extract_frames(Path('signal-2021-11-29-22-02-26.backup').read_bytes())
full_encrypted_frames = extract_frames(Path('signal-2021-11-30-00-18-47.backup').read_bytes())

print(len(my_backup_decrypted_frames), 'frames in my empty backup!')
print(len(empty_encrypted_frames), 'frames in encrypted empty backup!')
print(len(full_encrypted_frames), 'frames in encrypted full backup!')

# remove unrecoverable frames from full backup
full_encrypted_frames = full_encrypted_frames[:len(empty_encrypted_frames)]

# generate possibles aes streams
aes_streams = {}
for i, enc_frame in enumerate(empty_encrypted_frames):
    aes_streams[i] = []
    for dec_frame in my_backup_decrypted_frames:
        if abs(len(enc_frame) - len(dec_frame)) < 20:
            aes_streams[i].append(xor(enc_frame, dec_frame))

decrypted = b''
for i, enc_frame in enumerate(full_encrypted_frames):
    for aes_stream in aes_streams[i]:
        decrypted += xor(enc_frame, aes_stream)

Path('decrypted_chunks').write_bytes(decrypted)
print('Done!')

