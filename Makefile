NASM = nasm
LD_WIN = x86_64-w64-mingw32-ld

all: linux windows

linux: build/grotto

windows: build/grotto.exe

build/grotto: linux/main.asm
	$(NASM) -f elf64 -I shared/ -I linux/ -o build/grotto.o linux/main.asm
	wsl ld -o build/grotto build/grotto.o --strip-all
	@echo "[*] Linux binary: $$(wc -c < build/grotto) bytes"

build/grotto.exe: windows/main.asm
	$(NASM) -f win64 -I shared/ -I windows/ -o build/grotto.obj windows/main.asm
	$(LD_WIN) -e _start --stack 1048576,262144 -o build/grotto.exe build/grotto.obj --strip-all
	@echo "[*] Windows binary: $$(wc -c < build/grotto.exe) bytes"

baked: baked-linux baked-windows

baked-linux:
	$(NASM) -f elf64 -DBAKED -I shared/ -I linux/ -I build/ -o build/grotto.o linux/main.asm
	wsl ld -o build/grotto build/grotto.o --strip-all
	@echo "[*] Linux binary (baked): $$(wc -c < build/grotto) bytes"

baked-windows:
	$(NASM) -f win64 -DBAKED -I shared/ -I windows/ -I build/ -o build/grotto.obj windows/main.asm
	$(LD_WIN) -e _start --stack 1048576,262144 -o build/grotto.exe build/grotto.obj --strip-all
	@echo "[*] Windows binary (baked): $$(wc -c < build/grotto.exe) bytes"

clean:
	rm -f build/*

.PHONY: all linux windows baked baked-linux baked-windows clean
