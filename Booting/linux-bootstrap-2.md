커널 부팅 과정. Part 2
================================================================================

커널 구성의 첫 단계
--------------------------------------------------------------------------------

우리는 [지난 시간](linux-bootstrap-1.md)에 리눅스 커널의 내부로 진입을 시작했고 커널 구성 코드의 일부를 살펴봤습니다. 우리는 [arch/x86/boot/main.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c)의 `main`함수를 처음으로 호출하는 데에서 멈췄었습니다. (C로 짜여진 첫 번째 함수죠)

이번 시간엔, 커널 구성 코드를 더 파헤처보고 아래 것들에 대해 알아봅시다.
* `protected mode`란 무엇인가
* `protected mode`로의 이행
* 힙과 콘솔의 초기화
* 메모리 탐지, CPU 유효성 검사 그리고 키보드 초기화
* 그리고 많고 많은 것들

그럼 가시죠.

보호 모드(Protected mode)
--------------------------------------------------------------------------------

네이티브 Intel64 [Long Mode](http://en.wikipedia.org/wiki/Long_mode)로 가기 전에, 커널은 CPU를 보호 모드로 전환해야만 합니다.

[보호 모드](https://ko.wikipedia.org/wiki/%EB%B3%B4%ED%98%B8_%EB%AA%A8%EB%93%9C)([protected mode](https://en.wikipedia.org/wiki/Protected_mode))가 뭘까요? 보호 모드는 1982년에 x86 아키텍처에 처음 추가되었고, [80286](http://en.wikipedia.org/wiki/Intel_80286) 프로세서부터 Intel 64와 long mode가 등장하기 전까지 인텔 프로세들의 메인 모드였습니다.

[리얼 모드](https://ko.wikipedia.org/wiki/%EB%A6%AC%EC%96%BC_%EB%AA%A8%EB%93%9C)([Real mode](http://wiki.osdev.org/Real_Mode))에서 옮겨온 가장 큰 이유는 RAM에 굉장히 한정적인 접근만 가능했기 때문이었습니다. 이전 시간에서 얘기했던 것처럼, 오직 2<sup>20</sup> 바이트 또는 1 메가바이트만 가능했고, 어떤 때는 리얼 모드에서 오로지 RAM의 640 킬로바이트만 사용가능했습니다.

보호 모드는 많은 변화를 가져왔지만 그 중 메인은 메모리 관리의 변화였습니다. 20비트 주소 버스는 32비트 주소 버스로 교체되었습니다. 이는 실제 모드에서 1메가바이트만 접근가능했던 것과는 달리 4기가바이트에 달하는 메모리에 접근 가능하게 해주었습니다. 또한, [페이징]( [https://ko.wikipedia.org/wiki/%ED%8E%98%EC%9D%B4%EC%A7%95](https://ko.wikipedia.org/wiki/페이징) )([paging](http://en.wikipedia.org/wiki/Paging)) 지원이 추가되어, 페이징으로 다음 구역을 읽을 수 있게 되었습니다.

보호 모드의 메모리 관리는 거의 독립적인 두 부분으로 나뉩니다.

* 분할 (세그먼트)
* 페이징

여기서는 분할에 대해서만 다루고, 페이징은 다음 시간에 다루도록 하겠습니다.

이전 시간에서 읽었듯, 리얼 모드에서 주소는 두 부분으로 구성됩니다.

* 세그먼트의 베이스 주소
* 세그먼트 베이스로 부터의 오프셋

그리고 이 두 부분을 알고 있다면 다음과 같이 물리적 주소를 알 수 있습니다.

```
PhysicalAddress = Segment Selector * 16 + Offset
```

보호 모드에서 메모리 세그먼트 방식은 완전히 재구성되었습니다. 64 킬로바이트의 고정 크기 세그먼트는 사라졌습니다. 대신에, 각 세그먼트의 크기와 위치는 _세그먼트 디스크립터(Segment Descriptor)_라는 자료구조에 기록되었습니다.  세그먼트 디스크립터는 `Global Descriptor Table` (GDT)라고 불리는 자료구조에 저장되었습니다.

GDT는 메모리 내에 존재하는 구조체입니다. GDT의 자리는 메모리 내에 고정되어 있지 않아서 그 주소가 특별한 `GDTR` 레지스터에 저장됩니다. 나중에 리눅스 커널 코드에서 어떻게 GDT가 로드되는지 살펴볼 겁니다. `lgdt`명령어가 베이스 주소와 GDT의 제한(크기)를 `GDTR` 레지스터에 가져오는 곳에 GDT를 메모리로 로드하기 위한 동작이 다음과 같이 있을 것입니다.

```assembly
lgdt gdt
```

 `GDTR` 는 48비트 레지스터이며 두 부분으로 이루어저 있습니다.

 * GDT의 크기 (16-bit) ;
 * GDT의 주소 (32-bit) .

위에서 언급한 것처럼, GDT는 메모리 세그먼트를 기록하는 `세그먼트 디스크립터`를 포함하고 있습니다.  각각의 디스크립터는 64비트의 크기를 갖고 있습니다. 세그먼트 디스크립터의 일반적인 구성은 다음과 같습니다:

```
 63         56         51   48    45           39        32 
------------------------------------------------------------
|             | |B| |A|       | |   | |0|E|W|A|            |
| BASE 31:24  |G|/|L|V| LIMIT |P|DPL|S|  TYPE | BASE 23:16 |
|             | |D| |L| 19:16 | |   | |1|C|R|A|            |
------------------------------------------------------------

 31                         16 15                         0 
------------------------------------------------------------
|                             |                            |
|        BASE 15:0            |       LIMIT 15:0           |
|                             |                            |
------------------------------------------------------------
```

리얼 모드에서 넘어오니 좀 무서워보일 수 있지만 걱정 마세요, 사실 쉽습니다. 예를 들어 LIMIT 15:0 는 Limit의 0-15번째 비트가 디스크립터의 시작 부분에 위치한다는 것을 의미합니다. 나머지 부분들은 LIMIT 19:16에 들어있고, 이는 디스크립터의 48-51번째 비트에 위치해 있습니다. 그래서 Limit의 크기는 0-19 즉, 20 비트가 되는 것입니다. 이에 대해 조금 더 자세히 살펴봅시다.

1. Limit[20 비트] 는 비트 0-15 와 48-51로 나누어집니다. 이는 `length_of_segment - 1` 값을 나타내고, `G`(Granularity) 비트에 의해 좌우됩니다.

  * 만약 `G` (비트 55) 가 0이고 segment limit도 0이면, 세그먼트의 크기는 1 Byte입니다.
  * 만약 `G` 가 1이고 segment limit가 0이면, 세그먼트의 크기는 4096 Byte입니다.
  * 만약 `G` 가 0이고 segment limit가 0xfffff이면, 세그먼트의 크기는 1 MByte입니다.
  * 만약 `G` 가 1이고 segment limit가 0xfffff이면, 세그먼트의 크기는 4 GByte입니다.

 이말인 즉슨,
  * 만약 G가 0이면, Limit 은 1 바이트로 해석되고, 세그먼트의 최대 크기는 1 메가바이트가 된다.
  * 만약 G가 1이면, Limit 은 4096 Bytes = 4 KBytes = 1 Page 로 해석되고 세그먼트의 최대 크기는 4 기가바이트가 된다. 사실, G가 1일 때, Limit의 값은 왼쪽으로 12비트 이동(shift)된다. 그러므로 20 bit + 12 bit = 32 bit이고 2<sup>32</sup> = 4 Gigabytes이다.

2. Base[32-bits] 는 16-31번째, 32-39번째, 그리고 56-63번째 비트들 사이에서 쪼개진다. 이것은 세그먼트의 시작 위치의 물리적 주소를 나타낸다.

3. Type/Attribute[5-bits] 는 40-44번째 비트로 나타내어진다. 이것은 세그먼트의 종류와 어떻게 접근 가능한지를 나타낸다.
  * 44번째 비트의 `S` 플래그는 디스크립터의 종류를 특정합니다. 만약 `S`가 0이면 이 세그먼트는 시스템 세그먼트이고, 만약 `S`가 1이면 이것은 코드 혹은 데이터 세그먼트입니다. (스택 세그먼트는 데이터 세그먼트이고, 읽기/쓰기 세그먼트여야 합니다.).

특정 세그먼트가 코드 세그먼트인지 데이터 세그먼트인지 판별하기 위해서는, 그것의 Ex 속성(43번 비트)을 확인하면 됩니다 (위 다이어그램에는 0으로 표기되어있음). 만약 0이면, 그 세그먼트는 데이터 세그먼트이고, 그렇지 않다면 그건 코드 세그먼트입니다.

세그먼트는 다양한 타입이 될 수 있는데 이는 다음과 같습니다.

```
--------------------------------------------------------------------------------------
|           Type Field        | Descriptor Type | Description                        |
|-----------------------------|-----------------|------------------------------------|
| Decimal                     |                 |                                    |
|             0    E    W   A |                 |                                    |
| 0           0    0    0   0 | Data            | Read-Only                          |
| 1           0    0    0   1 | Data            | Read-Only, accessed                |
| 2           0    0    1   0 | Data            | Read/Write                         |
| 3           0    0    1   1 | Data            | Read/Write, accessed               |
| 4           0    1    0   0 | Data            | Read-Only, expand-down             |
| 5           0    1    0   1 | Data            | Read-Only, expand-down, accessed   |
| 6           0    1    1   0 | Data            | Read/Write, expand-down            |
| 7           0    1    1   1 | Data            | Read/Write, expand-down, accessed  |
|                  C    R   A |                 |                                    |
| 8           1    0    0   0 | Code            | Execute-Only                       |
| 9           1    0    0   1 | Code            | Execute-Only, accessed             |
| 10          1    0    1   0 | Code            | Execute/Read                       |
| 11          1    0    1   1 | Code            | Execute/Read, accessed             |
| 12          1    1    0   0 | Code            | Execute-Only, conforming           |
| 14          1    1    0   1 | Code            | Execute-Only, conforming, accessed |
| 13          1    1    1   0 | Code            | Execute/Read, conforming           |
| 15          1    1    1   1 | Code            | Execute/Read, conforming, accessed |
--------------------------------------------------------------------------------------
```

위 표에서 볼 수 있듯, 첫 번째 비트(43번 비트)가  `0`이면 _데이터_ 세그먼트이고 `1`이면 _코드_ 세그먼트입니다. 다음 세 비트 (40, 41, 42)는 `EWA`(*E*xpansion *W*ritable *A*ccessible) 이거나 `CRA`(*C*onforming *R*eadable *A*ccessible)입니다.
  * 만약 E(42번 비트)가 0이면, 위로 확장하고, 1이면 아래로 확장합니다. [여기](http://www.sudleyplace.com/dpmione/expanddown.html)서 더 알아보세요.
  * 만약 (데이터 세그먼트인 경우에) W(41번 비트)가 1이라면, 쓰기 엑세스가 허용됩니다. 반대로 0일 경우엔, 읽기 전용이 됩니다.  데이터 세그먼트에서는 항상 읽기 액세스가 허용된다는 점에 유의하세요. 
  * A(40번 비트)는 프로세서에서 세그먼트에 액세스할 수 있는지 여부를 제어합니다. 
  * C(43번 비트)는 호환 비트입니다(코드 선택기의 경우). C가 1이면 낮은 수준 권한(예: 사용자)에서도 세그먼트 코드를 실행할 수 있습니다. C가 0이면 동등한 권한 레벨에서만 실행할 수 있습니다. 
  * R(41번 비트)은 코드 세그먼트에 대한 읽기 액세스를 제어합니다. 이 값이 1이면 세그먼트를 읽을 수 있습니다. 코드 세그먼트에 대해서는 쓰기 액세스 권한이 부여되지 않습니다. 

4. DPL[2비트] (Descriptor 권한 수준)은 45-46번 비트로 구성됩니다. 이것은 세그먼트의 권한 수준을 정의합니다. 0-3의 값을 가질 수 있는데 여기서 0이 가장 높은 권한 수준입니다. 

5. P 플래그(47번 비트)는 세그먼트가 메모리에 있는지의 여부를 나타냅니다. P가 0이면 세그먼트가 _invalid_로 표시되고 프로세서가 이 세그먼트에서 읽기를 거부합니다. 

6. AVL 플래그(52번 비트) - 사용도 가능하고 이를 위해 자리도 예약된 비트이지만 Linux에서는 무시됩니다. 

7.  L 플래그(53번 비트)는 코드 세그먼트에 네이티브 64비트 코드가 포함되어 있는지 여부를 나타냅니다. 플래그가 설정되어 있는 경우, 해당 코드 세그먼트는 64비트 모드로 실행됩니다. 

8.  D/B 플래그(54번 비트)(기본/빅 플래그)는 피연산자 크기(예: 16/32비트)를 나타냅니다. 설정된 경우 피연산자 크기는 32비트입니다. 그렇지 않으면 16비트입니다. 

Segment registers contain segment selectors as in real mode. However, in protected mode, a segment selector is handled differently. Each Segment Descriptor has an associated Segment Selector which is a 16-bit structure:

```
 15             3 2  1     0
-----------------------------
|      Index     | TI | RPL |
-----------------------------
```

Where,
* **Index** stores the index number of the descriptor in the GDT.
* **TI**(Table Indicator) indicates where to search for the descriptor. If it is 0 then the descriptor is searched for in the Global Descriptor Table(GDT). Otherwise, it will be searched for in the Local Descriptor Table(LDT).
* And **RPL** contains the Requester's Privilege Level.

Every segment register has a visible and a hidden part.
* Visible - The Segment Selector is stored here.
* Hidden -  The Segment Descriptor (which contains the base, limit, attributes & flags) is stored here.

The following steps are needed to get a physical address in protected mode:

* The segment selector must be loaded in one of the segment registers.
* The CPU tries to find a segment descriptor at the offset `GDT address + Index` from the selector and then loads the descriptor into the *hidden* part of the segment register.
* If paging is disabled, the linear address of the segment, or its physical address, is given by the formula: Base address (found in the descriptor obtained in the previous step) + Offset.

Schematically it will look like this:

![linear address](http://oi62.tinypic.com/2yo369v.jpg)

The algorithm for the transition from real mode into protected mode is:

* Disable interrupts
* Describe and load the GDT with the `lgdt` instruction
* Set the PE (Protection Enable) bit in CR0 (Control Register 0)
* Jump to protected mode code

We will see the complete transition to protected mode in the linux kernel in the next part, but before we can move to protected mode, we need to do some more preparations.

Let's look at [arch/x86/boot/main.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c). We can see some routines there which perform keyboard initialization, heap initialization, etc... Let's take a look.

Copying boot parameters into the "zeropage"
--------------------------------------------------------------------------------

We will start from the `main` routine in "main.c". The first function which is called in `main` is [`copy_boot_params(void)`](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c). It copies the kernel setup header into the corresponding field of the `boot_params` structure which is defined in the [arch/x86/include/uapi/asm/bootparam.h](https://github.com/torvalds/linux/blob/v4.16/arch/x86/include/uapi/asm/bootparam.h) header file.

The `boot_params` structure contains the `struct setup_header hdr` field. This structure contains the same fields as defined in the [linux boot protocol](https://www.kernel.org/doc/Documentation/x86/boot.txt) and is filled by the boot loader and also at kernel compile/build time. `copy_boot_params` does two things:

1. It copies `hdr` from [header.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/header.S#L280) to the `setup_header` field in `boot_params` structure.

2. It updates the pointer to the kernel command line if the kernel was loaded with the old command line protocol.

Note that it copies `hdr` with the `memcpy` function, defined in the [copy.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/copy.S) source file. Let's have a look inside:

```assembly
GLOBAL(memcpy)
    pushw   %si
    pushw   %di
    movw    %ax, %di
    movw    %dx, %si
    pushw   %cx
    shrw    $2, %cx
    rep; movsl
    popw    %cx
    andw    $3, %cx
    rep; movsb
    popw    %di
    popw    %si
    retl
ENDPROC(memcpy)
```

Yeah, we just moved to C code and now assembly again :) First of all, we can see that `memcpy` and other routines which are defined here, start and end with the two macros: `GLOBAL` and `ENDPROC`. `GLOBAL` is described in [arch/x86/include/asm/linkage.h](https://github.com/torvalds/linux/blob/v4.16/arch/x86/include/asm/linkage.h) which defines the `globl` directive and its label. `ENDPROC` is described in [include/linux/linkage.h](https://github.com/torvalds/linux/blob/v4.16/include/linux/linkage.h) and marks the `name` symbol as a function name and ends with the size of the `name` symbol.

The implementation of `memcpy` is simple. At first, it pushes values from the `si` and `di` registers to the stack to preserve their values because they will change during the `memcpy`. As we can see in the `REALMODE_CFLAGS` in `arch/x86/Makefile`, the kernel build system uses the `-mregparm=3` option of GCC, so functions get the first three parameters from `ax`, `dx` and `cx` registers.  Calling `memcpy` looks like this:

```c
memcpy(&boot_params.hdr, &hdr, sizeof hdr);
```

So,
* `ax` will contain the address of `boot_params.hdr`
* `dx` will contain the address of `hdr`
* `cx` will contain the size of `hdr` in bytes.

`memcpy` puts the address of `boot_params.hdr` into `di` and saves `cx` on the stack. After this it shifts the value right 2 times (or divides it by 4) and copies four bytes from the address at `si` to the address at `di`. After this, we restore the size of `hdr` again, align it by 4 bytes and copy the rest of the bytes from the address at `si` to the address at `di` byte by byte (if there is more). Now the values of `si` and `di` are restored from the stack and the copying operation is finished.

Console initialization
--------------------------------------------------------------------------------

After `hdr` is copied into `boot_params.hdr`, the next step is to initialize the console by calling the `console_init` function,  defined in [arch/x86/boot/early_serial_console.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/early_serial_console.c).

It tries to find the `earlyprintk` option in the command line and if the search was successful, it parses the port address and baud rate of the serial port and initializes the serial port. The value of the `earlyprintk` command line option can be one of these:

* serial,0x3f8,115200
* serial,ttyS0,115200
* ttyS0,115200

After serial port initialization we can see the first output:

```C
if (cmdline_find_option_bool("debug"))
    puts("early console in setup code\n");
```

The definition of `puts` is in [tty.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/tty.c). As we can see it prints character by character in a loop by calling the `putchar` function. Let's look into the `putchar` implementation:

```C
void __attribute__((section(".inittext"))) putchar(int ch)
{
    if (ch == '\n')
        putchar('\r');

    bios_putchar(ch);

    if (early_serial_base != 0)
        serial_putchar(ch);
}
```

`__attribute__((section(".inittext")))` means that this code will be in the `.inittext` section. We can find it in the linker file [setup.ld](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/setup.ld).

First of all, `putchar` checks for the `\n` symbol and if it is found, prints `\r` before. After that it prints the character on the VGA screen by calling the BIOS with the `0x10` interrupt call:

```C
static void __attribute__((section(".inittext"))) bios_putchar(int ch)
{
    struct biosregs ireg;

    initregs(&ireg);
    ireg.bx = 0x0007;
    ireg.cx = 0x0001;
    ireg.ah = 0x0e;
    ireg.al = ch;
    intcall(0x10, &ireg, NULL);
}
```

Here `initregs` takes the `biosregs` structure and first fills `biosregs` with zeros using the `memset` function and then fills it with register values.

```C
    memset(reg, 0, sizeof *reg);
    reg->eflags |= X86_EFLAGS_CF;
    reg->ds = ds();
    reg->es = ds();
    reg->fs = fs();
    reg->gs = gs();
```

Let's look at the implementation of [memset](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/copy.S#L36):

```assembly
GLOBAL(memset)
    pushw   %di
    movw    %ax, %di
    movzbl  %dl, %eax
    imull   $0x01010101,%eax
    pushw   %cx
    shrw    $2, %cx
    rep; stosl
    popw    %cx
    andw    $3, %cx
    rep; stosb
    popw    %di
    retl
ENDPROC(memset)
```

As you can read above, it uses the same calling conventions as the `memcpy` function, which means that the function gets its parameters from the `ax`, `dx` and `cx` registers.

The implementation of `memset` is similar to that of memcpy. It saves the value of the `di` register on the stack and puts the value of`ax`, which stores the address of the `biosregs` structure, into `di` . Next is the `movzbl` instruction, which copies the value of `dl` to the lower 2 bytes of the `eax` register. The remaining 2 high bytes  of `eax` will be filled with zeros.

The next instruction multiplies `eax` with `0x01010101`. It needs to because `memset` will copy 4 bytes at the same time. For example, if we need to fill a structure whose size is 4 bytes with the value `0x7` with memset, `eax` will contain the `0x00000007`. So if we multiply `eax` with `0x01010101`, we will get `0x07070707` and now we can copy these 4 bytes into the structure. `memset` uses the `rep; stosl` instruction to copy `eax` into `es:di`.

The rest of the `memset` function does almost the same thing as `memcpy`.

After the `biosregs` structure is filled with `memset`, `bios_putchar` calls the [0x10](http://www.ctyme.com/intr/rb-0106.htm) interrupt which prints a character. Afterwards it checks if the serial port was initialized or not and writes a character there with [serial_putchar](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/tty.c) and `inb/outb` instructions if it was set.

Heap initialization
--------------------------------------------------------------------------------

After the stack and bss section have been prepared in [header.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/header.S) (see previous [part](linux-bootstrap-1.md)), the kernel needs to initialize the [heap](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c) with the [`init_heap`](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c) function.

First of all `init_heap` checks the [`CAN_USE_HEAP`](https://github.com/torvalds/linux/blob/v4.16/arch/x86/include/uapi/asm/bootparam.h#L24) flag from the [`loadflags`](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/header.S#L320) structure in the kernel setup header and calculates the end of the stack if this flag was set:

```C
    char *stack_end;

    if (boot_params.hdr.loadflags & CAN_USE_HEAP) {
        asm("leal %P1(%%esp),%0"
            : "=r" (stack_end) : "i" (-STACK_SIZE));
```

or in other words `stack_end = esp - STACK_SIZE`.

Then there is the `heap_end` calculation:

```C
     heap_end = (char *)((size_t)boot_params.hdr.heap_end_ptr + 0x200);
```

which means `heap_end_ptr` or `_end` + `512` (`0x200h`). The last check is whether `heap_end` is greater than `stack_end`. If it is then `stack_end` is assigned to `heap_end` to make them equal.

Now the heap is initialized and we can use it using the `GET_HEAP` method. We will see what it is used for, how to use it and how it is implemented in the next posts.

CPU validation
--------------------------------------------------------------------------------

The next step as we can see is cpu validation through the `validate_cpu` function from [arch/x86/boot/cpu.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/cpu.c) source code file.

It calls the [`check_cpu`](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/cpucheck.c) function and passes cpu level and required cpu level to it and checks that the kernel launches on the right cpu level.

```C
check_cpu(&cpu_level, &req_level, &err_flags);
if (cpu_level < req_level) {
    ...
    return -1;
}
```

The `check_cpu` function checks the CPU's flags, the presence of [long mode](http://en.wikipedia.org/wiki/Long_mode) in the case of x86_64(64-bit) CPU, checks the processor's vendor and makes preparations for certain vendors like turning off SSE+SSE2 for AMD if they are missing, etc.

at the next step, we may see a call to the `set_bios_mode` function after setup code found that a CPU is suitable. As we may see, this function is implemented only for the `x86_64` mode:

```C
static void set_bios_mode(void)
{
#ifdef CONFIG_X86_64
	struct biosregs ireg;

	initregs(&ireg);
	ireg.ax = 0xec00;
	ireg.bx = 2;
	intcall(0x15, &ireg, NULL);
#endif
}
```

The `set_bios_mode` function executes the `0x15` BIOS interrupt to tell the BIOS that [long mode](https://en.wikipedia.org/wiki/Long_mode) (if `bx == 2`) will be used.

Memory detection
--------------------------------------------------------------------------------

The next step is memory detection through the `detect_memory` function. `detect_memory` basically provides a map of available RAM to the CPU. It uses different programming interfaces for memory detection like `0xe820`, `0xe801` and `0x88`. We will see only the implementation of the **0xE820** interface here.

Let's look at the implementation of the `detect_memory_e820` function from the [arch/x86/boot/memory.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/memory.c) source file. First of all, the `detect_memory_e820` function initializes the `biosregs` structure as we saw above and fills registers with special values for the `0xe820` call:

```assembly
    initregs(&ireg);
    ireg.ax  = 0xe820;
    ireg.cx  = sizeof buf;
    ireg.edx = SMAP;
    ireg.di  = (size_t)&buf;
```

* `ax` contains the number of the function (0xe820 in our case)
* `cx` contains the size of the buffer which will contain data about the memory
* `edx` must contain the `SMAP` magic number
* `es:di` must contain the address of the buffer which will contain memory data
* `ebx` has to be zero.

Next is a loop where data about the memory will be collected. It starts with a call to the `0x15` BIOS interrupt, which writes one line from the address allocation table. For getting the next line we need to call this interrupt again (which we do in the loop). Before the next call `ebx` must contain the value returned previously:

```C
    intcall(0x15, &ireg, &oreg);
    ireg.ebx = oreg.ebx;
```

Ultimately, this function collects data from the address allocation table and writes this data into the `e820_entry` array:

* start of memory segment
* size  of memory segment
* type of memory segment (whether the particular segment is usable or reserved)

You can see the result of this in the `dmesg` output, something like:

```
[    0.000000] e820: BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] reserved
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000003ffdffff] usable
[    0.000000] BIOS-e820: [mem 0x000000003ffe0000-0x000000003fffffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff] reserved
```

Keyboard initialization
--------------------------------------------------------------------------------

The next step is the initialization of the keyboard with a call to the [`keyboard_init`](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c) function. At first `keyboard_init` initializes registers using the `initregs` function. It then calls the [0x16](http://www.ctyme.com/intr/rb-1756.htm) interrupt to query the status of the keyboard.

```c
    initregs(&ireg);
    ireg.ah = 0x02;     /* Get keyboard status */
    intcall(0x16, &ireg, &oreg);
    boot_params.kbd_status = oreg.al;
```

After this it calls [0x16](http://www.ctyme.com/intr/rb-1757.htm) again to set the repeat rate and delay.

```c
    ireg.ax = 0x0305;   /* Set keyboard repeat rate */
    intcall(0x16, &ireg, NULL);
```

Querying
--------------------------------------------------------------------------------

The next couple of steps are queries for different parameters. We will not dive into details about these queries but we will get back to them in later parts. Let's take a short look at these functions:

The first step is getting [Intel SpeedStep](http://en.wikipedia.org/wiki/SpeedStep) information by calling the `query_ist` function. It checks the CPU level and if it is correct, calls `0x15` to get the info and saves the result to `boot_params`.

Next, the [query_apm_bios](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/apm.c#L21) function gets [Advanced Power Management](http://en.wikipedia.org/wiki/Advanced_Power_Management) information from the BIOS. `query_apm_bios` calls the `0x15` BIOS interruption too, but with `ah` = `0x53` to check `APM` installation. After `0x15` finishes executing, the `query_apm_bios` functions check the `PM` signature (it must be `0x504d`), the carry flag (it must be 0 if `APM` supported) and the value of the `cx` register (if it's 0x02, the protected mode interface is supported).

Next, it calls `0x15` again, but with `ax = 0x5304` to disconnect the `APM` interface and connect the 32-bit protected mode interface. In the end, it fills `boot_params.apm_bios_info` with values obtained from the BIOS.

Note that `query_apm_bios` will be executed only if the `CONFIG_APM` or `CONFIG_APM_MODULE` compile time flag was set in the configuration file:

```C
#if defined(CONFIG_APM) || defined(CONFIG_APM_MODULE)
    query_apm_bios();
#endif
```

The last is the [`query_edd`](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/edd.c#L122) function, which queries `Enhanced Disk Drive` information from the BIOS. Let's look at how `query_edd` is implemented.

First of all, it reads the [edd](https://github.com/torvalds/linux/blob/v4.16/Documentation/admin-guide/kernel-parameters.rst) option from the kernel's command line and if it was set to `off` then `query_edd` just returns.

If EDD is enabled, `query_edd` goes over BIOS-supported hard disks and queries EDD information in the following loop:

```C
for (devno = 0x80; devno < 0x80+EDD_MBR_SIG_MAX; devno++) {
    if (!get_edd_info(devno, &ei) && boot_params.eddbuf_entries < EDDMAXNR) {
        memcpy(edp, &ei, sizeof ei);
        edp++;
        boot_params.eddbuf_entries++;
    }
    ...
    ...
    ...
    }
```

where `0x80` is the first hard drive and the value of the `EDD_MBR_SIG_MAX` macro is 16. It collects data into an array of [edd_info](https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/edd.h) structures. `get_edd_info` checks that EDD is present by invoking the `0x13` interrupt with `ah` as `0x41` and if EDD is present, `get_edd_info` again calls the `0x13` interrupt, but with `ah` as `0x48` and `si` containing the address of the buffer where EDD information will be stored.

Conclusion
--------------------------------------------------------------------------------

This is the end of the second part about the insides of the Linux kernel. In the next part, we will see video mode setting and the rest of the preparations before the transition to protected mode and directly transitioning into it.

If you have any questions or suggestions write me a comment or ping me at [twitter](https://twitter.com/0xAX).

**Please note that English is not my first language, And I am really sorry for any inconvenience. If you find any mistakes please send me a PR to [linux-insides](https://github.com/0xAX/linux-internals).**

Links
--------------------------------------------------------------------------------

* [Protected mode](http://en.wikipedia.org/wiki/Protected_mode)
* [Protected mode](http://wiki.osdev.org/Protected_Mode)
* [Long mode](http://en.wikipedia.org/wiki/Long_mode)
* [Nice explanation of CPU Modes with code](http://www.codeproject.com/Articles/45788/The-Real-Protected-Long-mode-assembly-tutorial-for)
* [How to Use Expand Down Segments on Intel 386 and Later CPUs](http://www.sudleyplace.com/dpmione/expanddown.html)
* [earlyprintk documentation](https://github.com/torvalds/linux/blob/v4.16/Documentation/x86/earlyprintk.txt)
* [Kernel Parameters](https://github.com/torvalds/linux/blob/v4.16/Documentation/admin-guide/kernel-parameters.rst)
* [Serial console](https://github.com/torvalds/linux/blob/v4.16/Documentation/admin-guide/serial-console.rst)
* [Intel SpeedStep](http://en.wikipedia.org/wiki/SpeedStep)
* [APM](https://en.wikipedia.org/wiki/Advanced_Power_Management)
* [EDD specification](http://www.t13.org/documents/UploadedDocuments/docs2004/d1572r3-EDD3.pdf)
* [TLDP documentation for Linux Boot Process](http://www.tldp.org/HOWTO/Linux-i386-Boot-Code-HOWTO/setup.html) (old)
* [Previous Part](linux-bootstrap-1.md)
