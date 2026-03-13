NASM = nasm
LD_WIN = x86_64-w64-mingw32-ld

all: linux windows

linux: build/ncat

windows: build/ncat.exe

build/ncat: linux/main.asm
	$(NASM) -f elf64 -I shared/ -I linux/ -o build/ncat.o linux/main.asm
	wsl ld -o build/ncat build/ncat.o --strip-all
	@echo "[*] Linux binary: $$(wc -c < build/ncat) bytes"

build/ncat.exe: windows/main.asm
	$(NASM) -f win64 -I shared/ -I windows/ -o build/ncat.obj windows/main.asm
	$(LD_WIN) -o build/ncat.exe build/ncat.obj --strip-all
	@echo "[*] Windows binary: $$(wc -c < build/ncat.exe) bytes"

clean:
	rm -f build/*

.PHONY: all linux windows clean
