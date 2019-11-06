커널 부팅 프로세스. Part 5.
================================================================================

Kernel decompression
--------------------------------------------------------------------------------

이것은 `커널 부팅 프로세스` 시리즈의 다섯 번 째 파트입니다. 우리는 이전 [파트](https://github.com/0xAX/linux-insides/blob/v4.16/Bootinglinux-bootstrap-4.md#transition-to-the-long-mode)에서 64비트 모드로 전환하는 것을 보았고 이 시점에서 계속 진행 할 것입니다. 우리는 커널 압축 해제, 재배치 및 직접 커널 압축 해제에 대한 준비로 커널 코드로 도약하기 전에 마지막 단계를 보게 될 것입니다. 다시 커널 코드를 살펴봅시다.

커널 디컴프레션 전 준비해야할 사항
--------------------------------------------------------------------------------

우리는 `64-bit` 엔트리 포인트에서 점프하기 직전에 멈췄습니다. `startup_64` [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S) 소스 코드 파일에 위치한. 우리는 이미 `startup_32`에서 `startup_64`로 점프하는 것을 보았습니다.

```assembly
	pushl	$__KERNEL_CS
	leal	startup_64(%ebp), %eax
	...
	...
	...
	pushl	%eax
	...
	...
	...
	lret
```

이전 부분에서, 새로운 `Global Descriptor Table`을 로드하고 다른 모드 (이 경우에는 64비트 모드)에서 CPU  전환이 있었으므로 데이터 세그먼트의 설정을 볼 수 있습니다.

```assembly
	.code64
	.org 0x200
ENTRY(startup_64)
	xorl	%eax, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %fs
	movl	%eax, %gs
```

`startup_64`를 시작하는 부분에서, `cs` 레지스터 이외의 모든 세그먼트 레지스터는 `long mode`에 참가할 때 재설정됩니다.

다음 단계는 커널이 컴파일 된 위치와 로드 된 위치의 차이를 계산하는 것입니다.

```assembly
#ifdef CONFIG_RELOCATABLE
	leaq	startup_32(%rip), %rbp
	movl	BP_kernel_alignment(%rsi), %eax
	decl	%eax
	addq	%rax, %rbp
	notq	%rax
	andq	%rax, %rbp
	cmpq	$LOAD_PHYSICAL_ADDR, %rbp
	jge	1f
#endif
	movq	$LOAD_PHYSICAL_ADDR, %rbp
1:
	movl	BP_init_size(%rsi), %ebx
	subl	$_end, %ebx
	addq	%rbp, %rbx
```

`rbp` 는 디컴프레스 된 커널 시작 주소를 포함하고 이 코드가 실행된 후에 `rbx` 레지스터는 디컴프레스를 위해 커널 코드를 재배치하기 위한 주소를 포함합니다. 우리는 이미 `startup_32`에서 이와 같은 코드를 보았습니다.( 이전 부분에서 읽을 수 있습니다. - [이전 주소 계산](https://github.com/0xAX/linux-insides/blob/v4.16/Booting/linux-bootstrap-4.md#calculate-relocation-address)), 하지만 부트로더가 64 비트 부팅 프로토콜을 사용할 수 있고 `startup_32`는 이 경우 실행되지 않으므로 이 계산을 다시 수행해야 합니다.

다음 단계에서 스택 포인터의 설정을 볼 수 있습니다. `64비트` 프로토콜의 경우 `32비트` 코드 세그먼트는 부트로더에 의해 생략될 수 있기 때문에 플래그 레지스터와 GDT를 재설정 해야 합니다. 

```assembly
    leaq	boot_stack_end(%rbx), %rsp

    leaq	gdt(%rip), %rax
    movq	%rax, gdt64+2(%rip)
    lgdt	gdt64(%rip)

    pushq	$0
    popfq
```

`lgdt gdt64(%rip)` 명령 후 리눅스 커널 소스 코드를 보면, 추가 코드가 있음을 알 수 있습니다. 이 코드는 필요한 경우[5-level pagging](https://lwn.net/Articles/708526/)을 성화 하기 위해 트럼팰린을 빌드합니다. 이 책에서는 4단계 페이징만 고려하므로 이 코드는 생략합니다.

위에서 본 것 처럼, `rbx` 레지스터는 커널 디컴프레서 코드의 시작 주소를 포함하고 우리는 이 주소를 `boot_stack_end` 오프셋을 스택 상단에 대한 포인터를 나타내는 `rsp` 레지스터에 넣습니다. 이 단계가 끝나면 스택은 정확할 것입니다.  You can find definition of the `boot_stack_end` in the end of [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S) 어셈블리 소스 파일:

```assembly
	.bss
	.balign 4
boot_heap:
	.fill BOOT_HEAP_SIZE, 1, 0
boot_stack:
	.fill BOOT_STACK_SIZE, 1, 0
boot_stack_end:
```

그것은 `.pgtable` 바로 앞에 있는 `.bss` 섹션 끝에 있습니다.[arch/x86/boot/compressed/vmlinux.lds.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/vmlinux.lds.S)를 살펴 보면, 링커 스크립트에는 `.bss` 및 `.pgtable`의 정의가 있습니다.

스택을 설정하면 디컴프레션된 커널의 재배치 주소를 계산할 때 디컴프레션된 커널을 위에서 얻은 주소로 복사할 수 있습니다. 세부 사항을 작성하기 전에, 아래의 어셈블리 코드를 살펴 보겠습니다.

```assembly
	pushq	%rsi
	leaq	(_bss-8)(%rip), %rsi
	leaq	(_bss-8)(%rbx), %rdi
	movq	$_bss, %rcx
	shrq	$3, %rcx
	std
	rep	movsq
	cld
	popq	%rsi
```

우선 우리는 스택에 `rsi`를 넣습니다. 이 레지스터는 이제 부팅 관련 데이터를 포함하는 리얼 모드 구조 인`boot_params`에 대한 포인터를 저장하기 때문에 rsi 값을 보존해야합니다 (이 구조를 기억해야합니다. 커널 설정의 시작 부분에 채웠습니다). 이 코드의 끝에서 우리는 `boot_params` 에 대한 포인터를 `rsi` 에 다시 복원 할 것입니다.

다음 두 `leaq` 명령어는 `_bss-8` 오프셋으로 `rip` 및 `rbx`의 유효 주소를 계산하여 `rsi`와 `rdi`에 넣습니다. 왜 이 주소를 계산할까요? 실제로 디컴프레스된 커널 이미지는이 복사 코드 ( 'startup_32'에서 현재 코드로)와 디컴프레션 코드 사이에 있습니다. 링커 스크립트- [arch / x86 / boot / compressed / vmlinux.lds.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/vmlinux.lds.S)를 봐서 이를 확인할 수 있습니다.

```
	. = 0;
	.head.text : {
		_head = . ;
		HEAD_TEXT
		_ehead = . ;
	}
	.rodata..compressed : {
		*(.rodata..compressed)
	}
	.text :	{
		_text = .; 	/* Text */
		*(.text)
		*(.text.*)
		_etext = . ;
	}
```

`.head.text` 섹션에는`startup_32`가 포함되어 있습니다. 이전 부분에서 기억할 수 있습니다.

```assembly
	__HEAD
	.code32
ENTRY(startup_32)
...
...
...
```

`.text` 섹션은 디컴프레션 코드를 포함합니다 :

```assembly
	.text
relocated:
...
...
...
/*
 * Do the decompression, and jump to the new kernel..
 */
...
```

그리고 `.rodata..compressed`는 디컴프레스 된 커널 이미지를 포함합니다. 따라서 `rsi`는 `_bss-8`의 절대 주소를 포함하고 `rdi`는 `_bss-8`의 재배치 상대 주소를 포함합니다. 이 주소들을 레지스터에 저장함에 따라 `_bss`의 주소를`rcx` 레지스터에 넣습니다. `vmlinux.lds.S` 링커 스크립트에서 볼 수 있듯이, 설정 / 커널 코드가있는 모든 섹션의 끝에 있습니다. 이제 movsq 명령으로`rsi`에서 `rdi`,`8` 바이트의 데이터를 복사 할 수 있습니다.


데이터 복사 전에 `std` 명령이 있습니다 : 그것은 `DF` 플래그를 설정합니다. 이는 `rsi`와 `rdi`가 감소 함을 의미합니다. 즉, 바이트를 뒤로 복사합니다. 마지막으로, 우리는 `cld` 명령어로 `DF` 플래그를 지우고 `boot_params` 구조를 `rsi`로 복원합니다.

이제 우리는 재배치 후 `.text` 섹션의 주소를 가지게되었고, 우리는 그 주소로 이동할 수 있습니다 :

```assembly
	leaq	relocated(%rbx), %rax
	jmp	*%rax
```

커널 디컴프레션 전 마지막 준비
--------------------------------------------------------------------------------

이전 단락에서 우리는 `.text` 섹션이 재배치 된 레이블로 시작하는 것을 보았습니다. 가장 먼저하는 일은 `bss` 섹션을 지우는 것입니다 :

```assembly
	xorl	%eax, %eax
	leaq    _bss(%rip), %rdi
	leaq    _ebss(%rip), %rcx
	subq	%rdi, %rcx
	shrq	$3, %rcx
	rep	stosq
```

곧 [C](https://en.wikipedia.org/wiki/C_%28programming_language%29) 코드로 넘어 가기 때문에 `.bss` 섹션을 초기화해야합니다. 여기서는 `eax`를 지우고 `rdi`에 `_bss`와 `rcx`에 `_ebss`의 주소를 넣고 `rep stosq` 명령으로 0을 채웁니다.
마지막으로 `extract_kernel` 함수에 대한 호출을 볼 수 있습니다.

```assembly
	pushq	%rsi
	movq	%rsi, %rdi
	leaq	boot_heap(%rip), %rsi
	leaq	input_data(%rip), %rdx
	movl	$z_input_len, %ecx
	movq	%rbp, %r8
	movq	$z_output_len, %r9
	call	extract_kernel
	popq	%rsi
```

다시 우리는 `rdi`를 `boot_params` 구조의 포인터로 설정하고 스택에 보존합니다. 동시에 커널 디컴프레션에 사용될 영역을 가리키도록 `rsi`를 설정했습니다. 마지막 단계는 `extract_kernel` 매개 변수를 준비하고 커널을 분해하는 이 함수를 호출하는 것입니다. `extract_kernel` 함수는 [arch / x86 / boot / compressed / misc.](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/misc)에 정의되어 있습니다. .c) 소스 코드 파일이며 6 개의 인수를 사용합니다.

* `rmode` - pointer to the [boot_params](https://github.com/torvalds/linux/blob/v4.16/arch/x86/include/uapi/asm/bootparam.h) structure which is filled by bootloader or during early kernel initialization;
* `heap` - pointer to the `boot_heap` which represents start address of the early boot heap;
* `input_data` - pointer to the start of the compressed kernel or in other words pointer to the `arch/x86/boot/compressed/vmlinux.bin.bz2`;
* `input_len` - size of the compressed kernel;
* `output` - start address of the future decompressed kernel;
* `output_len` - size of decompressed kernel;

All arguments will be passed through the registers according to [System V Application Binary Interface](http://www.x86-64.org/documentation/abi.pdf). We've finished all preparation and can now look at the kernel decompression.

Kernel decompression
--------------------------------------------------------------------------------

As we saw in previous paragraph, the `extract_kernel` function is defined in the [arch/x86/boot/compressed/misc.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/misc.c) source code file and takes six arguments. This function starts with the video/console initialization that we already saw in the previous parts. We need to do this again because we don't know if we started in [real mode](https://en.wikipedia.org/wiki/Real_mode) or a bootloader was used, or whether the bootloader used the `32` or `64-bit` boot protocol.

After the first initialization steps, we store pointers to the start of the free memory and to the end of it:

```C
free_mem_ptr     = heap;
free_mem_end_ptr = heap + BOOT_HEAP_SIZE;
```

where the `heap` is the second parameter of the `extract_kernel` function which we got in the [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S):

```assembly
leaq	boot_heap(%rip), %rsi
```

As you saw above, the `boot_heap` is defined as:

```assembly
boot_heap:
	.fill BOOT_HEAP_SIZE, 1, 0
```

where the `BOOT_HEAP_SIZE` is macro which expands to `0x10000` (`0x400000` in a case of `bzip2` kernel) and represents the size of the heap.

After heap pointers initialization, the next step is the call of the `choose_random_location` function from [arch/x86/boot/compressed/kaslr.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/kaslr.c) source code file. As we can guess from the function name, it chooses the memory location where the kernel image will be decompressed. It may look weird that we need to find or even `choose` location where to decompress the compressed kernel image, but the Linux kernel supports [kASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) which allows decompression of the kernel into a random address, for security reasons.

We will not consider randomization of the Linux kernel load address in this part, but will do it in the next part.

Now let's back to [misc.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/misc.c). After getting the address for the kernel image, there need to be some checks to be sure that the retrieved random address is correctly aligned and address is not wrong:

```C
if ((unsigned long)output & (MIN_KERNEL_ALIGN - 1))
	error("Destination physical address inappropriately aligned");

if (virt_addr & (MIN_KERNEL_ALIGN - 1))
	error("Destination virtual address inappropriately aligned");

if (heap > 0x3fffffffffffUL)
	error("Destination address too large");

if (virt_addr + max(output_len, kernel_total_size) > KERNEL_IMAGE_SIZE)
	error("Destination virtual address is beyond the kernel mapping area");

if ((unsigned long)output != LOAD_PHYSICAL_ADDR)
    error("Destination address does not match LOAD_PHYSICAL_ADDR");

if (virt_addr != LOAD_PHYSICAL_ADDR)
	error("Destination virtual address changed when not relocatable");
```

After all these checks we will see the familiar message:

```
Decompressing Linux... 
```

and call the `__decompress` function:

```C
__decompress(input_data, input_len, NULL, NULL, output, output_len, NULL, error);
```

which will decompress the kernel. The implementation of the `__decompress` function depends on what decompression algorithm was chosen during kernel compilation:

```C
#ifdef CONFIG_KERNEL_GZIP
#include "../../../../lib/decompress_inflate.c"
#endif

#ifdef CONFIG_KERNEL_BZIP2
#include "../../../../lib/decompress_bunzip2.c"
#endif

#ifdef CONFIG_KERNEL_LZMA
#include "../../../../lib/decompress_unlzma.c"
#endif

#ifdef CONFIG_KERNEL_XZ
#include "../../../../lib/decompress_unxz.c"
#endif

#ifdef CONFIG_KERNEL_LZO
#include "../../../../lib/decompress_unlzo.c"
#endif

#ifdef CONFIG_KERNEL_LZ4
#include "../../../../lib/decompress_unlz4.c"
#endif
```

After kernel is decompressed, the last two functions are `parse_elf` and `handle_relocations`. The main point of these functions is to move the uncompressed kernel image to the correct memory place. The fact is that the decompression will decompress [in-place](https://en.wikipedia.org/wiki/In-place_algorithm), and we still need to move kernel to the correct address. As we already know, the kernel image is an [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) executable, so the main goal of the `parse_elf` function is to move loadable segments to the correct address. We can see loadable segments in the output of the `readelf` program:

```
readelf -l vmlinux

Elf file type is EXEC (Executable file)
Entry point 0x1000000
There are 5 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000200000 0xffffffff81000000 0x0000000001000000
                 0x0000000000893000 0x0000000000893000  R E    200000
  LOAD           0x0000000000a93000 0xffffffff81893000 0x0000000001893000
                 0x000000000016d000 0x000000000016d000  RW     200000
  LOAD           0x0000000000c00000 0x0000000000000000 0x0000000001a00000
                 0x00000000000152d8 0x00000000000152d8  RW     200000
  LOAD           0x0000000000c16000 0xffffffff81a16000 0x0000000001a16000
                 0x0000000000138000 0x000000000029b000  RWE    200000
```

The goal of the `parse_elf` function is to load these segments to the `output` address we got from the `choose_random_location` function. This function starts with checking the [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) signature:

```C
Elf64_Ehdr ehdr;
Elf64_Phdr *phdrs, *phdr;

memcpy(&ehdr, output, sizeof(ehdr));

if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
    ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
    ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
    ehdr.e_ident[EI_MAG3] != ELFMAG3) {
        error("Kernel is not a valid ELF file");
        return;
}
```

and if it's not valid, it prints an error message and halts. If we got a valid `ELF` file, we go through all program headers from the given `ELF` file and copy all loadable segments with correct 2 megabytes aligned address to the output buffer:

```C
	for (i = 0; i < ehdr.e_phnum; i++) {
		phdr = &phdrs[i];

		switch (phdr->p_type) {
		case PT_LOAD:
#ifdef CONFIG_X86_64
			if ((phdr->p_align % 0x200000) != 0)
				error("Alignment of LOAD segment isn't multiple of 2MB");
#endif                
#ifdef CONFIG_RELOCATABLE
			dest = output;
			dest += (phdr->p_paddr - LOAD_PHYSICAL_ADDR);
#else
			dest = (void *)(phdr->p_paddr);
#endif
			memmove(dest, output + phdr->p_offset, phdr->p_filesz);
			break;
		default:
			break;
		}
	}
```

That's all.

From this moment, all loadable segments are in the correct place.

The next step after the `parse_elf` function is the call of the `handle_relocations` function. Implementation of this function depends on the `CONFIG_X86_NEED_RELOCS` kernel configuration option and if it is enabled, this function adjusts addresses in the kernel image, and is called only if the `CONFIG_RANDOMIZE_BASE` configuration option was enabled during kernel configuration. Implementation of the `handle_relocations` function is easy enough. This function subtracts value of the `LOAD_PHYSICAL_ADDR` from the value of the base load address of the kernel and thus we obtain the difference between where the kernel was linked to load and where it was actually loaded. After this we can perform kernel relocation as we know actual address where the kernel was loaded, its address where it was linked to run and relocation table which is in the end of the kernel image.

After the kernel is relocated, we return back from the `extract_kernel` to [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S).

The address of the kernel will be in the `rax` register and we jump to it:

```assembly
jmp	*%rax
```

That's all. Now we are in the kernel!

Conclusion
--------------------------------------------------------------------------------

This is the end of the fifth part about linux kernel booting process. We will not see posts about kernel booting anymore (maybe updates to this and previous posts), but there will be many posts about other kernel internals. 

Next chapter will describe more advanced details about linux kernel booting process, like a load address randomization and etc.

If you have any questions or suggestions write me a comment or ping me in [twitter](https://twitter.com/0xAX).

**Please note that English is not my first language, And I am really sorry for any inconvenience. If you find any mistakes please send me PR to [linux-insides](https://github.com/0xAX/linux-internals).**

Links
--------------------------------------------------------------------------------

* [address space layout randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
* [initrd](https://en.wikipedia.org/wiki/Initrd)
* [long mode](https://en.wikipedia.org/wiki/Long_mode)
* [bzip2](http://www.bzip.org/)
* [RdRand instruction](https://en.wikipedia.org/wiki/RdRand)
* [Time Stamp Counter](https://en.wikipedia.org/wiki/Time_Stamp_Counter)
* [Programmable Interval Timers](https://en.wikipedia.org/wiki/Intel_8253)
* [Previous part](https://github.com/0xAX/linux-insides/blob/v4.16/Booting/linux-bootstrap-4.md)
