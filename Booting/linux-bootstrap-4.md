커널 부팅 과정. 4 부.
================================================================================

64 bit 모드로 전환
--------------------------------------------------------------------------------

 커널 부팅 프로세스의 네 번째 부분으로 우리는 [보호 모드](http://en.wikipedia.org/wiki/Protected_mode) 첫 단계를 배울 것 입니다. CPU가 [롱 모드](http://en.wikipedia.org/wiki/Long_mode) 와 [SSE](http://en.wikipedia.org/wiki/Streaming_SIMD_Extensions)를 지원하는지 확인하고, [페이징](http://en.wikipedia.org/wiki/Paging), 페이지 테이블을 초기화하기 등 결국 우리는 [롱 모드](https://en.wikipedia.org/wiki/Long_mode)로의 전환에 대해 논의합니다.

**NOTE: there will be much assembly code in this part, so if you are not familiar with that, you might want to consult a book about it**

이전 [부분](https://github.com/0xAX/linux-insides/blob/v4.16/Booting/linux-bootstrap-3.md)에서 우리는 [arch/x86/boot/pmjump.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/pmjump.S)의 `32-bit` 진입 점으로 점프하는 것을 멈췄습니다:

```assembly
jmpl	*%eax
```

우리는 eax 레지스터에는 32 비트 진입 점의 주소가 포함되어 있다는 것을 알 수 있었습니다. [리눅스 커널 x86 부팅 프로토콜](https://www.kernel.org/doc/Documentation/x86/boot.txt)에서 이것에 대해 읽을 수 있습니다:

```
bzImage를 사용할 때, 보호 모드 커널이 0x100000로 재배치 되었습니다.
```

32 비트 진입 점에서 레지스터 값을 확인하여 사실인지 확인해 봅시다:

```
eax            0x100000	1048576
ecx            0x0	    0
edx            0x0	    0
ebx            0x0	    0
esp            0x1ff5c	0x1ff5c
ebp            0x0	    0x0
esi            0x14470	83056
edi            0x0	    0
eip            0x100000	0x100000
eflags         0x46	    [ PF ZF ]
cs             0x10	16
ss             0x18	24
ds             0x18	24
es             0x18	24
fs             0x18	24
gs             0x18	24
```

 여기서 cs 레즈스터에 - `0x10` ([이전 부분](https://github.com/0xAX/linux-insides/blob/v4.16/Booting/linux-bootstrap-3.md)에서 기억할 수 있듯이, `Global Descriptor Table`의 두 번째 인덱스 인 것을 알 수 있습니다.)이 포함되어 있음을 알 수 있고, `eip` 레지스터에 `0x100000`이 포함되어 있으며 코드 세그먼트를 포함한 모든 세그먼트의 기본 주소는 0입니다.

따라서 실제 주소를 얻을 수 있습니다. 부팅 프로토콜에서 지정한대로, `0:0x100000` 또는 `0x100000` 입니다. 이제 32-bit 진입점부터 시작하겠습니다.

32-bit 진입점
--------------------------------------------------------------------------------

[arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S) 어셈블리 소스 코드 파일에서 `32-bit` 진입 점의 정의를 찾을 수 있습니다:

```assembly
	__HEAD
	.code32
ENTRY(startup_32)
....
....
....
ENDPROC(startup_32)
```

우선, 디렉토리 이름이 `compressed`인 이유는 무엇일까요? 실제로 `bzimage`는 압축 된 `vmlinux + 헤더 + 커널 설정 코드`입니다. 이전 내용에서 커널 설정 코드를 보았습니다. 따라서 `head_64.S`의 주요 목표는 롱 모드로 들어가서 준비한 다음 커널을 압축 해제하는 것입니다. 이 부분에서 커널 압축 해제까지의 모든 단계를 볼 수 있습니다.

`arch/x86/boot/compressed` 디렉터리에서 두개의 파일을 찾을 수 있습니다:

* [head_32.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_32.S)
* [head_64.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S)

이 책은 `x86_64`에만 관련되어 있기 때문에 `head_64.S` 소스 코드 파일 만 고려할 것입니다. [arch/x86/boot/compressed/Makefile](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/Makefile)을 봅시다. `make` 타깃을 찾을 수 있습니다:

```Makefile
vmlinux-objs-y := $(obj)/vmlinux.lds $(obj)/head_$(BITS).o $(obj)/misc.o \
	$(obj)/string.o $(obj)/cmdline.o \
	$(obj)/piggy.o $(obj)/cpuflags.o
```

`$(obj)/head_$(BITS).o`를 살펴봅시다.

이것은 `$(BITS)`가 `head_32.o` 또는 `head_64.o`로 설정된 것을 기반으로 연결할 파일을 선택한다는 의미입니다. `$(BITS)` 변수는 커널 구성에 따라 [arch/x86/Makefile](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/Makefile)의 다른 곳에 정의됩니다:

```Makefile
ifeq ($(CONFIG_X86_32),y)
        BITS := 32
        ...
        ...
else
        BITS := 64
        ...
        ...
endif
```

이제 시작 위치를 알았으니 해보겠습니다.

필요시 세그먼트를 다시 로드
--------------------------------------------------------------------------------

위에서 설명한 것처럼, [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/compressed/head_64.S)
어셈블리 소스 코드 파일에서 시작합니다. 먼저 startup_32 정의 전에 특수 섹션 속성의 정의를 봅니다:

```assembly
    __HEAD
    .code32
ENTRY(startup_32)
```

`__HEAD`는 [include / linux / init.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/init.h) 헤더 파일에 정의 된 매크로이며 다음 섹션의 정의를 확장한다:

```C
#define __HEAD		.section	".head.text","ax"
```

`.head.text` 이름과 `ax` 플래그와 함께. 이 경우이 플래그는이 섹션이 [실행 가능](https://en.wikipedia.org/wiki/Executable)이거나 다른 말로 코드를 포함하고 있음을 나타냅니다. 이 섹션의 정의는 [arch / x86 / boot / compressed / vmlinux.lds.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/compressed/vmlinux에서 찾을 수 있습니다. .lds.S) 링커 스크립트:

```
SECTIONS
{
	. = 0;
	.head.text : {
		_head = . ;
		HEAD_TEXT
		_ehead = . ;
     }
     ...
     ...
     ...
}
```

`GNU LD` 링커 스크립팅 언어의 구문에 익숙하지 않은 경우 [documentation](https://sourceware.org/binutils/docs/ld/Scripts.html#Scripts)에서 자세한 정보를 찾을 수 있습니다. 위치 카운터 - 즉,`.` 기호는 링커의 특별한 변수입니다. 여기에 할당 된 값은 세그먼트와 관련된 오프셋입니다. 이 경우 위치 카운터에 0을 할당합니다. 이것은 우리 코드가 메모리의`0` 오프셋에서 실행되도록 연결되어 있음을 의미합니다. 또한 이 정보를 주석에서 찾을 수 있습니다:

```
head_64.S의 부분은 startup_32가 주소 0에 있다고 가정하십시오.
```

자, 이제 우리는 현재 위치를 알고 있으며, 이제`startup_32` 함수를 살펴보기에 가장 좋은 시간입니다.

`startup_32` 함수의 시작 부분에서 우리는 [flags](https://en.wikipedia.org/wiki/FLAGS_register) 레지스터에서 DF 비트를 지우는 cld 명령을 볼 수 있습니다. 방향 플래그가 지워지면 [stos](http://x86.renejeschke.de/html/file_module_x86_id_306.html), [scas](http://x86.renejeschke.de/html/file_module_x86_id_287.html과 같은 모든 문자열 작업 ) 및 기타는 인덱스 레지스터 `esi` 또는`edi`를 증가시킵니다. 나중에 페이지 테이블 등의 공간을 비우기 위해 문자열 연산을 사용하므로 방향 플래그를 지워야합니다.

DF 비트를 클리어 한 후 다음 단계는 loadflags 커널 설정 헤더 필드에서`KEEP_SEGMENTS` 플래그를 점검하는 것입니다. 우리가 이미 기억한다면이 책의 맨 처음 부분(https://0xax.gitbooks.io/linux-insides/content/Booting/linux-bootstrap-1.html)에서 'loadflags'를 보았습니다. 거기에서 힙을 사용하는 능력을 얻기 위해`CAN_USE_HEAP` 플래그를 확인했습니다. 이제 'KEEP_SEGMENTS'플래그를 확인해야합니다. 이 플래그는 리눅스 [부팅 프로토콜](https://www.kernel.org/doc/Documentation/x86/boot.txt) 문서에 설명되어 있습니다:

```
Bit 6 (write): KEEP_SEGMENTS
  Protocol: 2.07+
  - If 0, reload the segment registers in the 32bit entry point.
  - If 1, do not reload the segment registers in the 32bit entry point.
    Assume that %cs %ds %ss %es are all set to flat segments with
		a base of 0 (or the equivalent for their environment).
```

따라서 만약 `KEEP_SEGMENTS` 비트가 `loadflags`에 설정되어 있지 않다면, `ds`,`ss` 및 `es` 세그먼트 레지스터를 기준이 `0` 인 데이터 세그먼트의 인덱스로 설정해야합니다. 우리가하는 일:

```C
	testb $KEEP_SEGMENTS, BP_loadflags(%esi)
	jnz 1f

	cli
	movl	$(__BOOT_DS), %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
```

`__BOOT_DS`는 `0x18` ([Global Descriptor Table](https://en.wikipedia.org/wiki/Global_Descriptor_Table)의 데이터 세그먼트 색인)입니다. 만약 'KEEP_SEGMENTS'가 설정되면 가장 가까운 '1f'레이블로 이동하거나 설정되지 않은 경우 '__BOOT_DS'로 세그먼트 레지스터를 업데이트합니다. 꽤 쉽지만 여기서 흥미로운 순간이 있습니다. 이전의 [part](https://github.com/0xAX/linux-insides/blob/v4.16/Booting/linux-bootstrap-3.md)를 읽었다면 이미 업데이트 된 것을 기억할 것입니다 [arch / x86 / boot / pmjump.S](https://github.com/torvalds/linux)에서 [보호 모드](https://en.wikipedia.org/wiki/Protected_mode)로 전환 한 직후 세그먼트 레지스터 /blob/v4.16/arch/x86/boot/pmjump.S). 그렇다면 왜 세그먼트 레지스터의 값을 다시 신경 써야합니까? 대답은 쉽습니다. 리눅스 커널은 32 비트 부트 프로토콜을 가지고 있으며 부트 로더가이를 사용하여 리눅스 커널을로드한다면`startup_32`가 나오기 전에 모든 코드를 놓치게됩니다. 이 경우,`startup_32`는 부트 로더 바로 다음에 Linux 커널의 첫 번째 진입 점이 될 것이며 세그먼트 레지스터가 알려진 상태에 있다는 보장은 없습니다.

`KEEP_SEGMENTS` 플래그를 확인하고 세그먼트 레지스터에 올바른 값을 넣은 후 다음 단계는 로드하고 컴파일하여 실행하는 위치의 차이를 계산하는 것입니다. `setup.ld.S`에는 다음 정의가 포함되어 있습니다. `.head.text` 섹션 시작시 0 =. 이것은이 섹션의 코드가 `0` 주소에서 실행되도록 컴파일되었음을 의미합니다. 우리는 `objdump` 출력에서 ​​이것을 볼 수 있습니다:

```
arch/x86/boot/compressed/vmlinux:     파일 포맷 elf64-x86-64


.head.text 섹션의 분해 :

0000000000000000 <startup_32>:
   0:   fc                      cld
   1:   f6 86 11 02 00 00 40    testb  $0x40,0x211(%rsi)
```

`objdump` 유틸리티는`startup_32`의 주소가`0 '이라고 알려주지 만 실제로는 그렇지 않습니다. 우리의 현재 목표는 실제로 우리가 어디에 있는지 아는 것입니다. `rip` 상대 주소 지정을 지원하기 때문에 [long mode](https://en.wikipedia.org/wiki/Long_mode)에서하는 것이 매우 간단하지만 현재는 [protected mode](https : // en .wikipedia.org / wiki / Protected_mode). `startup_32`의 주소를 알기 위해 공통 패턴을 사용할 것입니다. 레이블을 정의하고이 레이블을 호출하고 스택의 상단을 레지스터로 팝해야합니다.

```assembly
call label
label: pop %reg
```

그 후,`% reg` 레지스터는 레이블의 주소를 포함 할 것입니다. 리눅스 커널에서`startup_32`의 주소를 검색하는 비슷한 코드를 보자 :

```assembly
        leal	(BP_scratch+4)(%esi), %esp
        call	1f
1:      popl	%ebp
        subl	$1b, %ebp
```

이전 부분에서 기억 하듯이`esi` 레지스터에는 [boot_params](https://github.com/torvalds/linux/blob/v4.16/arch/x86/include/uapi/asm/ 우리가 보호 모드로 이동하기 전에 채워진 bootparam.h # L113) 구조. `boot_params` 구조는 오프셋이 0x1e4 인 특수 필드 'scratch'를 포함합니다. 이 4 바이트 필드는`call` 명령을위한 임시 스택입니다. `scratch` 필드 +`4` 바이트의 주소를 가져 와서`esp` 레지스터에 넣습니다. 방금 설명한 것처럼 임시 스택이되고 스택은`x86_64` 아키텍처에서 위에서 아래로 커지기 때문에 'BP_scratch'필드의베이스에`4` 바이트를 추가합니다. 따라서 스택 포인터는 스택의 상단을 가리 킵니다. 다음으로 위에서 설명한 패턴을 볼 수 있습니다. `call` 명령어가 실행 된 후 스택 맨 위에 리턴 주소가 있으므로`1f` 레이블을 호출하고이 레이블의 주소를`ebp` 레지스터에 넣습니다. 이제 우리는`1f` 레이블의 주소를 가지게되었고 이제는`startup_32`의 주소를 얻는 것이 쉽습니다. 스택에서 얻은 주소에서 레이블 주소를 빼면됩니다:

```
startup_32 (0x0)     +-----------------------+
                     |                       |
                     |                       |
                     |                       |
                     |                       |
                     |                       |
                     |                       |
                     |                       |
                     |                       |
1f (0x0 + 1f offset) +-----------------------+ %ebp - real physical address
                     |                       |
                     |                       |
                     +-----------------------+
```

The `startup_32` is linked to run at address `0x0` and this means that `1f` has the address `0x0 + offset to 1f`, approximately `0x21` bytes. The `ebp` register contains the real physical address of the `1f` label. So, if we subtract `1f` from the `ebp` we will get the real physical address of the `startup_32`. The Linux kernel [boot protocol](https://www.kernel.org/doc/Documentation/x86/boot.txt) describes that the base of the protected mode kernel is `0x100000`. We can verify this with [gdb](https://en.wikipedia.org/wiki/GNU_Debugger). Let's start the debugger and put breakpoint to the `1f` address, which is `0x100021`. If this is correct we will see `0x100021` in the `ebp` register:

```
$ gdb
(gdb)$ target remote :1234
Remote debugging using :1234
0x0000fff0 in ?? ()
(gdb)$ br *0x100022
Breakpoint 1 at 0x100022
(gdb)$ c
Continuing.

Breakpoint 1, 0x00100022 in ?? ()
(gdb)$ i r
eax            0x18	0x18
ecx            0x0	0x0
edx            0x0	0x0
ebx            0x0	0x0
esp            0x144a8	0x144a8
ebp            0x100021	0x100021
esi            0x142c0	0x142c0
edi            0x0	0x0
eip            0x100022	0x100022
eflags         0x46	[ PF ZF ]
cs             0x10	0x10
ss             0x18	0x18
ds             0x18	0x18
es             0x18	0x18
fs             0x18	0x18
gs             0x18	0x18
```

If we execute the next instruction, `subl $1b, %ebp`, we will see:

```
(gdb) nexti
...
...
...
ebp            0x100000	0x100000
...
...
...
```

Ok, that's true. The address of the `startup_32` is `0x100000`. After we know the address of the `startup_32` label, we can prepare for the transition to [long mode](https://en.wikipedia.org/wiki/Long_mode). Our next goal is to setup the stack and verify that the CPU supports long mode and [SSE](http://en.wikipedia.org/wiki/Streaming_SIMD_Extensions).

Stack setup and CPU verification
--------------------------------------------------------------------------------

We could not setup the stack while we did not know the address of the `startup_32` label. We can imagine the stack as an array and the stack pointer register `esp` must point to the end of this array. Of course, we can define an array in our code, but we need to know its actual address to configure the stack pointer in a correct way. Let's look at the code:

```assembly
	movl	$boot_stack_end, %eax
	addl	%ebp, %eax
	movl	%eax, %esp
```

The `boot_stack_end` label, defined in the same [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S) assembly source code file and located in the [.bss](https://en.wikipedia.org/wiki/.bss) section:

```assembly
	.bss
	.balign 4
boot_heap:
	.fill BOOT_HEAP_SIZE, 1, 0
boot_stack:
	.fill BOOT_STACK_SIZE, 1, 0
boot_stack_end:
```

First of all, we put the address of `boot_stack_end` into the `eax` register, so the `eax` register contains the address of `boot_stack_end` where it was linked, which is `0x0 + boot_stack_end`. To get the real address of `boot_stack_end`, we need to add the real address of the `startup_32`. As you remember, we have found this address above and put it to the `ebp` register. In the end, the register `eax` will contain real address of the `boot_stack_end` and we just need to put to the stack pointer.

After we have set up the stack, next step is CPU verification. As we are going to execute transition to the `long mode`, we need to check that the CPU supports `long mode` and `SSE`. We will do it by the call of the `verify_cpu` function:

```assembly
	call	verify_cpu
	testl	%eax, %eax
	jnz	no_longmode
```

This function defined in the [arch/x86/kernel/verify_cpu.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/kernel/verify_cpu.S) assembly file and just contains a couple of calls to the [cpuid](https://en.wikipedia.org/wiki/CPUID) instruction. This instruction is used for getting information about the processor. In our case, it checks `long mode` and `SSE` support and returns `0` on success or `1` on fail in the `eax` register.

If the value of the `eax` is not zero, we jump to the `no_longmode` label which just stops the CPU by the call of the `hlt` instruction while no hardware interrupt will not happen:

```assembly
no_longmode:
1:
	hlt
	jmp     1b
```

If the value of the `eax` register is zero, everything is ok and we are able to continue.

Calculate relocation address
--------------------------------------------------------------------------------

The next step is calculating relocation address for decompression if needed. First, we need to know what it means for a kernel to be `relocatable`. We already know that the base address of the 32-bit entry point of the Linux kernel is `0x100000`, but that is a 32-bit entry point. The default base address of the Linux kernel is determined by the value of the `CONFIG_PHYSICAL_START` kernel configuration option. Its default value is `0x1000000` or `16 MB`. The main problem here is that if the Linux kernel crashes, a kernel developer must have a `rescue kernel` for [kdump](https://www.kernel.org/doc/Documentation/kdump/kdump.txt) which is configured to load from a different address. The Linux kernel provides special configuration option to solve this problem: `CONFIG_RELOCATABLE`. As we can read in the documentation of the Linux kernel:

```
This builds a kernel image that retains relocation information
so it can be loaded someplace besides the default 1MB.

Note: If CONFIG_RELOCATABLE=y, then the kernel runs from the address
it has been loaded at and the compile time physical address
(CONFIG_PHYSICAL_START) is used as the minimum location.
```

In simple terms, this means that the Linux kernel with the same configuration can be booted from different addresses. Technically, this is done by compiling the decompressor as [position independent code](https://en.wikipedia.org/wiki/Position-independent_code). If we look at [arch/x86/boot/compressed/Makefile](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/Makefile), we will see that the decompressor is indeed compiled with the `-fPIC` flag:

```Makefile
KBUILD_CFLAGS += -fno-strict-aliasing -fPIC
```

When we are using position-independent code an address is obtained by adding the address field of the instruction to the value of the program counter. We can load code which uses such addressing from any address. That's why we had to get the real physical address of `startup_32`. Now let's get back to the Linux kernel code. Our current goal is to calculate an address where we can relocate the kernel for decompression. Calculation of this address depends on `CONFIG_RELOCATABLE` kernel configuration option. Let's look at the code:

```assembly
#ifdef CONFIG_RELOCATABLE
	movl	%ebp, %ebx
	movl	BP_kernel_alignment(%esi), %eax
	decl	%eax
	addl	%eax, %ebx
	notl	%eax
	andl	%eax, %ebx
	cmpl	$LOAD_PHYSICAL_ADDR, %ebx
	jge	1f
#endif
	movl	$LOAD_PHYSICAL_ADDR, %ebx
```

Remember that the value of the `ebp` register is the physical address of the `startup_32` label. If the `CONFIG_RELOCATABLE` kernel configuration option is enabled during kernel configuration, we put this address in the `ebx` register, align it to a multiple of `2MB` and compare it with the `LOAD_PHYSICAL_ADDR` value. The `LOAD_PHYSICAL_ADDR` macro is defined in the [arch/x86/include/asm/boot.h](https://github.com/torvalds/linux/blob/v4.16/arch/x86/include/asm/boot.h) header file and it looks like this:

```C
#define LOAD_PHYSICAL_ADDR ((CONFIG_PHYSICAL_START \
				+ (CONFIG_PHYSICAL_ALIGN - 1)) \
				& ~(CONFIG_PHYSICAL_ALIGN - 1))
```

As we can see it just expands to the aligned `CONFIG_PHYSICAL_ALIGN` value which represents the physical address of where to load the kernel. After comparison of the `LOAD_PHYSICAL_ADDR` and value of the `ebx` register, we add the offset from the `startup_32` where to decompress the compressed kernel image. If the `CONFIG_RELOCATABLE` option is not enabled during kernel configuration, we just put the default address where to load kernel and add `z_extract_offset` to it.

After all of these calculations, we will have `ebp` which contains the address where we loaded it and `ebx` set to the address of where kernel will be moved after decompression. But that is not the end. The compressed kernel image should be moved to the end of the decompression buffer to simplify calculations where kernel will be located later. For this:

```assembly
1:
    movl	BP_init_size(%esi), %eax
    subl	$_end, %eax
    addl	%eax, %ebx
```

we put value from the `boot_params.BP_init_size` (or kernel setup header value from the `hdr.init_size`) to the `eax` register. The `BP_init_size` contains larger value between compressed and uncompressed [vmlinux](https://en.wikipedia.org/wiki/Vmlinux). Next we subtract address of the `_end` symbol from this value and add the result of subtraction to `ebx` register which will stores base address for kernel decompression.

Preparation before entering long mode
--------------------------------------------------------------------------------

When we have the base address where we will relocate the compressed kernel image, we need to do one last step before we can transition to 64-bit mode. First, we need to update the [Global Descriptor Table](https://en.wikipedia.org/wiki/Global_Descriptor_Table) with 64-bit segments because an relocatable kernel may be runned at any address below 512G:

```assembly
	addl	%ebp, gdt+2(%ebp)
	lgdt	gdt(%ebp)
```

Here we adjust base address of the Global Descriptor table to the address where we actually loaded and load the `Global Descriptor Table` with the `lgdt` instruction.

To understand the magic with `gdt` offsets we need to look at the definition of the `Global Descriptor Table`. We can find its definition in the same source code [file](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S):

```assembly
	.data
gdt64:
	.word	gdt_end - gdt
	.long	0
	.word	0
	.quad   0
gdt:
	.word	gdt_end - gdt
	.long	gdt
	.word	0
	.quad	0x00cf9a000000ffff	/* __KERNEL32_CS */
	.quad	0x00af9a000000ffff	/* __KERNEL_CS */
	.quad	0x00cf92000000ffff	/* __KERNEL_DS */
	.quad	0x0080890000000000	/* TS descriptor */
	.quad   0x0000000000000000	/* TS continued */
gdt_end:
```

We can see that it is located in the `.data` section and contains five descriptors: the first is `32-bit` descriptor for kernel code segment, `64-bit` kernel segment, kernel data segment and two task descriptors.

We already loaded the `Global Descriptor Table` in the previous [part](https://github.com/0xAX/linux-insides/blob/v4.16/Booting/linux-bootstrap-3.md), and now we're doing almost the same here, but descriptors with `CS.L = 1` and `CS.D = 0` for execution in `64` bit mode. As we can see, the definition of the `gdt` starts from two bytes: `gdt_end - gdt` which represents the last byte in the `gdt` table or table limit. The next four bytes contains base address of the `gdt`.

After we have loaded the `Global Descriptor Table` with `lgdt` instruction, we must enable [PAE](http://en.wikipedia.org/wiki/Physical_Address_Extension) by putting the value of `cr4` register into `eax`, setting the 5th bit and loading it back into `cr4`:

```assembly
	movl	%cr4, %eax
	orl	$X86_CR4_PAE, %eax
	movl	%eax, %cr4
```

Now we are almost finished with all preparations before we can move into 64-bit mode. The last step is to build page tables, but before that, here is some information about long mode.

Long mode
--------------------------------------------------------------------------------

The [Long mode](https://en.wikipedia.org/wiki/Long_mode) is the native mode for [x86_64](https://en.wikipedia.org/wiki/X86-64) processors. First, let's look at some differences between `x86_64` and the `x86`.

The `64-bit` mode provides features such as:

* New 8 general purpose registers from `r8` to `r15` + all general purpose registers are 64-bit now;
* 64-bit instruction pointer - `RIP`;
* New operating mode - Long mode;
* 64-Bit Addresses and Operands;
* RIP Relative Addressing (we will see an example of it in the next parts).

Long mode is an extension of legacy protected mode. It consists of two sub-modes:

* 64-bit mode;
* compatibility mode.

To switch into `64-bit` mode we need to do following things:

* Enable [PAE](https://en.wikipedia.org/wiki/Physical_Address_Extension);
* Build page tables and load the address of the top level page table into the `cr3` register;
* Enable `EFER.LME`;
* Enable paging.

We already enabled `PAE` by setting the `PAE` bit in the `cr4` control register. Our next goal is to build the structure for [paging](https://en.wikipedia.org/wiki/Paging). We will see this in next paragraph.

Early page table initialization
--------------------------------------------------------------------------------

So, we already know that before we can move into `64-bit` mode, we need to build page tables, so, let's look at the building of early `4G` boot page tables.

**NOTE: I will not describe the theory of virtual memory here. If you need to know more about it, see links at the end of this part.**

The Linux kernel uses `4-level` paging, and we generally build 6 page tables:

* One `PML4` or `Page Map Level 4` table with one entry;
* One `PDP` or `Page Directory Pointer` table with four entries;
* Four Page Directory tables with a total of `2048` entries.

Let's look at the implementation of this. First of all, we clear the buffer for the page tables in memory. Every table is `4096` bytes, so we need clear `24` kilobyte buffer:

```assembly
	leal	pgtable(%ebx), %edi
	xorl	%eax, %eax
	movl	$(BOOT_INIT_PGT_SIZE/4), %ecx
	rep	stosl
```

We put the address of `pgtable` plus `ebx` (remember that `ebx` contains the address to relocate the kernel for decompression) in the `edi` register, clear the `eax` register and set the `ecx` register to `6144`.

The `rep stosl` instruction will write the value of the `eax` to `edi`, increase value of the `edi` register by `4` and decrease the value of the `ecx` register by `1`. This operation will be repeated while the value of the `ecx` register is greater than zero. That's why we put `6144` or `BOOT_INIT_PGT_SIZE/4` in `ecx`.

The `pgtable` is defined at the end of [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S) assembly file and is:

```assembly
	.section ".pgtable","a",@nobits
	.balign 4096
pgtable:
	.fill BOOT_PGT_SIZE, 1, 0
```

As we can see, it is located in the `.pgtable` section and its size depends on the `CONFIG_X86_VERBOSE_BOOTUP` kernel configuration option:

```C
#  ifdef CONFIG_X86_VERBOSE_BOOTUP
#   define BOOT_PGT_SIZE	(19*4096)
#  else /* !CONFIG_X86_VERBOSE_BOOTUP */
#   define BOOT_PGT_SIZE	(17*4096)
#  endif
# else /* !CONFIG_RANDOMIZE_BASE */
#  define BOOT_PGT_SIZE		BOOT_INIT_PGT_SIZE
# endif
```

After we have got buffer for the `pgtable` structure, we can start to build the top level page table - `PML4` - with:

```assembly
	leal	pgtable + 0(%ebx), %edi
	leal	0x1007 (%edi), %eax
	movl	%eax, 0(%edi)
```

Here again, we put the address of the `pgtable` relative to `ebx` or in other words relative to address of the `startup_32` to the `edi` register. Next, we put this address with offset `0x1007` in the `eax` register. The `0x1007` is `4096` bytes which is the size of the `PML4` plus `7`. The `7` here represents flags of the `PML4` entry. In our case, these flags are `PRESENT+RW+USER`. In the end, we just write first the address of the first `PDP` entry to the `PML4`.

In the next step we will build four `Page Directory` entries in the `Page Directory Pointer` table with the same `PRESENT+RW+USE` flags:

```assembly
	leal	pgtable + 0x1000(%ebx), %edi
	leal	0x1007(%edi), %eax
	movl	$4, %ecx
1:  movl	%eax, 0x00(%edi)
	addl	$0x00001000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b
```

We put the base address of the page directory pointer which is `4096` or `0x1000` offset from the `pgtable` table in `edi` and the address of the first page directory pointer entry in `eax` register. Put `4` in the `ecx` register, it will be a counter in the following loop and write the address of the first page directory pointer table entry to the `edi` register. After this `edi` will contain the address of the first page directory pointer entry with flags `0x7`. Next we just calculate the address of following page directory pointer entries where each entry is `8` bytes, and write their addresses to `eax`. The last step of building paging structure is the building of the `2048` page table entries with `2-MByte` pages:

```assembly
	leal	pgtable + 0x2000(%ebx), %edi
	movl	$0x00000183, %eax
	movl	$2048, %ecx
1:  movl	%eax, 0(%edi)
	addl	$0x00200000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b
```

Here we do almost the same as in the previous example, all entries will be with flags - `$0x00000183` - `PRESENT + WRITE + MBZ`. In the end, we will have `2048` pages with `2-MByte` page or:

```python
>>> 2048 * 0x00200000
4294967296
```

`4G` page table. We just finished to build our early page table structure which maps `4` gigabytes of memory and now we can put the address of the high-level page table - `PML4` - in `cr3` control register:

```assembly
	leal	pgtable(%ebx), %eax
	movl	%eax, %cr3
```

That's all. All preparation are finished and now we can see transition to the long mode.

Transition to the 64-bit mode
--------------------------------------------------------------------------------

First of all we need to set the `EFER.LME` flag in the [MSR](http://en.wikipedia.org/wiki/Model-specific_register) to `0xC0000080`:

```assembly
	movl	$MSR_EFER, %ecx
	rdmsr
	btsl	$_EFER_LME, %eax
	wrmsr
```

Here we put the `MSR_EFER` flag (which is defined in [arch/x86/include/asm/msr-index.h](https://github.com/torvalds/linux/blob/v4.16/arch/x86/include/asm/msr-index.h)) in the `ecx` register and call `rdmsr` instruction which reads the [MSR](http://en.wikipedia.org/wiki/Model-specific_register) register. After `rdmsr` executes, we will have the resulting data in `edx:eax` which depends on the `ecx` value. We check the `EFER_LME` bit with the `btsl` instruction and write data from `eax` to the `MSR` register with the `wrmsr` instruction.

In the next step, we push the address of the kernel segment code to the stack (we defined it in the GDT) and put the address of the `startup_64` routine in `eax`.

```assembly
	pushl	$__KERNEL_CS
	leal	startup_64(%ebp), %eax
```

After this we push this address to the stack and enable paging by setting `PG` and `PE` bits in the `cr0` register:

```assembly
	pushl	%eax
    movl	$(X86_CR0_PG | X86_CR0_PE), %eax
	movl	%eax, %cr0
```

and execute:

```assembly
lret
```

instruction.

Remember that we pushed the address of the `startup_64` function to the stack in the previous step, and after the `lret` instruction, the CPU extracts the address of it and jumps there.

After all of these steps we're finally in 64-bit mode:

```assembly
	.code64
	.org 0x200
ENTRY(startup_64)
....
....
....
```

That's all!

Conclusion
--------------------------------------------------------------------------------

This is the end of the fourth part linux kernel booting process. If you have questions or suggestions, ping me in twitter [0xAX](https://twitter.com/0xAX), drop me [email](anotherworldofworld@gmail.com) or just create an [issue](https://github.com/0xAX/linux-insides/issues/new).

In the next part, we will see kernel decompression and much more.

**Please note that English is not my first language and I am really sorry for any inconvenience. If you find any mistakes please send me PR to [linux-insides](https://github.com/0xAX/linux-internals).**

Links
--------------------------------------------------------------------------------

* [Protected mode](http://en.wikipedia.org/wiki/Protected_mode)
* [Intel® 64 and IA-32 Architectures Software Developer’s Manual 3A](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html)
* [GNU linker](http://www.eecs.umich.edu/courses/eecs373/readings/Linker.pdf)
* [SSE](http://en.wikipedia.org/wiki/Streaming_SIMD_Extensions)
* [Paging](http://en.wikipedia.org/wiki/Paging)
* [Model specific register](http://en.wikipedia.org/wiki/Model-specific_register)
* [.fill instruction](http://www.chemie.fu-berlin.de/chemnet/use/info/gas/gas_7.html)
* [Previous part](https://github.com/0xAX/linux-insides/blob/v4.16/Booting/linux-bootstrap-3.md)
* [Paging on osdev.org](http://wiki.osdev.org/Paging)
* [Paging Systems](https://www.cs.rutgers.edu/~pxk/416/notes/09a-paging.html)
* [x86 Paging Tutorial](http://www.cirosantilli.com/x86-paging/)
