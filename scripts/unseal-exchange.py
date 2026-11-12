# One vsock connection. Send the sealed payload to the enclave, then record its one status line.
# The host pass line is exactly ARMED. DECLINED is a failure.
# The payload is written only to this process stdout, which socat connects to the vsock.
# Never write the payload file to the reply log or to stderr.
import sys

path = sys.argv[1]
with open(path, "rb") as handle:
    data = handle.read()
if not data.endswith(b"\n"):
    data += b"\n"
sys.stdout.buffer.write(data)
sys.stdout.buffer.flush()
line = sys.stdin.buffer.readline(200_000)
with open("/var/log/writ-unseal-reply.log", "wb") as out:
    out.write(line)
