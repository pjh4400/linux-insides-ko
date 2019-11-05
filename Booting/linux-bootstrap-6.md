Kernel booting process. Part 6.
================================================================================

Introduction
--------------------------------------------------------------------------------

커널 부팅 프로세스 시리즈의 여섯 번째 부분입니다. [이전 부분] (linux-bootstrap-5.md)에서 커널 부팅 프로세스의 끝을 보았습니다. 그러나 중요한 고급 부분을 건너 뛰었습니다.

리눅스 커널의 진입점은 LOAD_PHYSICAL_ADDR 주소로 실행되기 시작하는 소스코드 파일 [main.c] (https://github.com/torvalds/linux/blob/v4.16/init/main.c) 의 `start_kernel` 함수입니다. 소스 코드 파일이 LOAD_PHYSICAL_ADDR 주소에서 실행되기 시작했습니다. 이 주소는 디폴트로`0x1000000` 인 커널 구성 옵션 `CONFIG_PHYSICAL_START` 에 따라 다릅니다.:

```
config PHYSICAL_START
	hex "Physical address where the kernel is loaded" if (EXPERT || CRASH_DUMP)
	default "0x1000000"
	---help---
	  This gives the physical address where the kernel is loaded.
      ...
      ...
      ...
```

이 값은 커널 구성 중에 변경 될 수 있지만 로드 주소는 임의의 값으로 선택할 수 있습니다. 이를 위해 커널 구성 중에 커널 구성 옵션 `CONFIG_RANDOMIZE_BASE` 을 활성화해야합니다.

이 경우 Linux 커널 이미지를 압축 해제하고 로드할 실제 주소는 랜덤으로 지정됩니다. 이 부분에서는 이 옵션이 활성화되어있고 커널 이미지의 로드 주소가 [보안상의 이유로](https://en.wikipedia.org/wiki/Address_space_layout_randomization) 랜덤한 경우를 고려합니다.

페이지 테이블의 초기화
--------------------------------------------------------------------------------

커널 압축 해제 프로그램이 커널을 압축 해제하고 로드할 임의의 메모리 범위를 찾기 시작하기 전에 아이디 매핑 페이지 테이블을 초기화해야합니다. [bootloader] (https://en.wikipedia.org/wiki/Booting)에서 [16 비트 또는 32 비트 부트 프로토콜]을 사용하는 경우 (https://github.com/torvalds/linux/blob/v4.16/Documentation/x86/boot.txt)에 이미 페이지 테이블이 있습니다. 그러나 커널 압축 해제 프로그램이 메모리 범위 밖에서 메모리 범위를 선택하는 경우 필요에 따라 새 페이지가 필요할 수 있습니다. 그렇기 때문에 ID 매핑 페이지 테이블을 새로 만들어야합니다.

네, ID 매핑 된 페이지 테이블을 작성하는 것은 로드 주소를 랜덤화하는 첫 번째 단계 중 하나입니다. 그러나 우리가 그것을 고려하기 전에, 우리가 어디에서 왔는지 기억해 봅시다.

우리는 [이전 부분] (linux-bootstrap-5.md)에서 [long mode] (https://en.wikipedia.org/wiki/Long_mode)을 보았고, 커널 압축 해제 진입점인`extract_kernel` 함수로 이동합니다. 랜덤화는 다음 호출 함수:

```C
void choose_random_location(unsigned long input,
                            unsigned long input_size,
                            unsigned long *output,
                            unsigned long output_size,
                            unsigned long *virt_addr)
{}
```

에서 시작합니다. 보시다시피, 이 기능에는 다음과 같은 5 가지 매개 변수가 사용됩니다.

  * `input`;
  * `input_size`;
  * `output`;
  * `output_isze`;
  * `virt_addr`.

이 매개 변수가 무엇인지 이해해봅시다. 첫 번째 `input` 매개 변수는 [arch/x86/boot/compressed/misc.c] (https://github.com/torvalds/linux/blob/v4.16/arch)의 `extract_kernel` 함수의 매개 변수에서 가져왔습니다. /x86/boot/compressed/misc.c) 소스 코드 파일 :

```C
asmlinkage __visible void *extract_kernel(void *rmode, memptr heap,
				                          unsigned char *input_data,
				                          unsigned long input_len,
				                          unsigned char *output,
				                          unsigned long output_len)
{
  ...
  ...
  ...
  choose_random_location((unsigned long)input_data, input_len,
                         (unsigned long *)&output,
				         max(output_len, kernel_total_size),
				         &virt_addr);
  ...
  ...
  ...
}
```

이 매개 변수는 어셈블러 코드에서 전달됩니다.:

```C
leaq	input_data(%rip), %rdx
```

[arch/x86/boot/compressed/head_64.S] (https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S)에서 `input_data`는 작은 [mkpiggy] (https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/mkpiggy.c) 프로그램에 의해 생성됩니다. 리눅스 커널 소스 코드를 컴파일했다면 `linux/arch/x86/boot/compressed/piggy.S`에 있는 이 프로그램에 의해 생성 된 파일을 찾을 수 있습니다. 필자의 경우 이 파일은 다음과 같습니다.:


```assembly
.section ".rodata..compressed","a",@progbits
.globl z_input_len
z_input_len = 6988196
.globl z_output_len
z_output_len = 29207032
.globl input_data, input_data_end
input_data:
.incbin "arch/x86/boot/compressed/vmlinux.bin.gz"
input_data_end:
```
보시다시피 4 개의 전역 기호가 포함되어 있습니다. 압축된, 압축되지 않은 `vmlinux.bin.gz`의 크기인 처음 두 `z_input_len` 와 `z_output_len`, 세 번째는 우리의 `input_data` 이며, 알 수 있듯이 raw binary 형식의 Linux 커널 이미지를 가리킵니다(모든 디버깅 기호, 주석 및 재배치 정보가 제거됨). 마지막은 `input_data_end` 이며, 압축된 리눅스 이미지의 끝을 가리킵니다.

따라서 'choose_random_location'함수의 첫 번째 매개 변수는 `piggy.o` 오브젝트 파일에 임베드 된 압축 커널 이미지에 대한 포인터입니다.

`choose_random_location` 함수의 두 번째 매개 변수는 우리가 지금 본 `z_input_len`입니다.

'choose_random_location'함수의 세 번째 및 네 번째 매개 변수는 각각 압축 해제 된 커널 이미지를 배치할 위치와 압축 해제 된 커널 이미지의 길이입니다. 압축 해제 된 커널을 넣을 주소는 [arch/x86/boot/compressed/head_64.S] (https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S) 에서 나왔으며, 2MB 경계에 정렬 된 `startup_32`의 주소입니다. 압축 해제 된 커널의 크기는 동일한 `piggy.S` 에서 왔으며 `z_output_len` 입니다.

'choose_random_location' 함수의 마지막 매개 변수는 커널 로드 주소의 가상 주소입니다. 보시다시피 기본적으로 기본 실제 로드 주소와 일치합니다.:

```C
unsigned long virt_addr = LOAD_PHYSICAL_ADDR;
```

which depends on kernel configuration:

```C
#define LOAD_PHYSICAL_ADDR ((CONFIG_PHYSICAL_START \
				+ (CONFIG_PHYSICAL_ALIGN - 1)) \
				& ~(CONFIG_PHYSICAL_ALIGN - 1))
```

이제 'choose_random_location' 함수의 매개 변수를 이해했으므로 구현을 살펴 보겠습니다. 이 함수는 커널 명령 행에서 `nokaslr` 옵션을 체크하는 것으로 시작합니다 :

```C
if (cmdline_find_option_bool("nokaslr")) {
	warn("KASLR disabled: 'nokaslr' on cmdline.");
	return;
}
```

그리고 옵션이 주어지면 우리는`choose_random_location` 함수에서 나가고 커널 로드 주소는 랜덤화 되지 않을 것입니다. 관련 명령 행 옵션은 [커널 문서] (https://github.com/torvalds/linux/blob/v4.16/Documentation/admin-guide/kernel-parameters.rst)에서 찾을 수 있습니다.:

```
kaslr/nokaslr [X86]

Enable/disable kernel and module base offset ASLR
(Address Space Layout Randomization) if built into
the kernel. When CONFIG_HIBERNATION is selected,
kASLR is disabled by default. When kASLR is enabled,
hibernation will be disabled.
```

`nokaslr`을 커널 명령 행에 전달하지 않고 `CONFIG_RANDOMIZE_BASE` 커널 구성 옵션이 활성화되었다고 가정해 봅시다. 이 경우 커널로드 플래그에 'kASLR'플래그를 추가합니다.

```C
boot_params->hdr.loadflags |= KASLR_FLAG;
```

그리고 다음 단계에서 호출 되는 함수:

and the next step is the call of the:

```C
initialize_identity_maps();
```

는 [arch/x86/boot/compressed/kaslr_64.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/kaslr_64.c) 소스코드 파일에 정의되어 있습니다. 이 함수는`x86_mapping_info` 구조의 인스턴스인 `mapping_info`의 초기화에서 시작합니다.

```C
mapping_info.alloc_pgt_page = alloc_pgt_page;
mapping_info.context = &pgt_data;
mapping_info.page_flag = __PAGE_KERNEL_LARGE_EXEC | sev_me_mask;
mapping_info.kernpg_flag = _KERNPG_TABLE;
```

`x86_mapping_info` 구조는 [arch/x86/include/asm/init.h](https://github.com/torvalds/linux/blob/v4.16/arch/x86/include/asm/init.h) 헤더 파일과 모양에 정의되어 있습니다.:

```C
struct x86_mapping_info {
	void *(*alloc_pgt_page)(void *);
	void *context;
	unsigned long page_flag;
	unsigned long offset;
	bool direct_gbpages;
	unsigned long kernpg_flag;
};
```

This structure provides information about memory mappings. As you may remember from the previous part, we already setup'ed initial page tables from 0 up to `4G`. For now we may need to access memory above `4G` to load kernel at random position. So, the `initialize_identity_maps` function executes initialization of a memory region for a possible needed new page table. First of all let's try to look at the definition of the `x86_mapping_info` structure.

The `alloc_pgt_page` is a callback function that will be called to allocate space for a page table entry. The `context` field is an instance of the `alloc_pgt_data` structure in our case which will be used to track allocated page tables. The `page_flag` and `kernpg_flag` fields are page flags. The first represents flags for `PMD` or `PUD` entries. The second `kernpg_flag` field represents flags for kernel pages which can be overridden later. The `direct_gbpages` field represents support for huge pages and the last `offset` field represents offset between kernel virtual addresses and physical addresses up to `PMD` level.

The `alloc_pgt_page` callback just validates that there is space for a new page, allocates new page:

```C
entry = pages->pgt_buf + pages->pgt_buf_offset;
pages->pgt_buf_offset += PAGE_SIZE;
```

in the buffer from the:

```C
struct alloc_pgt_data {
	unsigned char *pgt_buf;
	unsigned long pgt_buf_size;
	unsigned long pgt_buf_offset;
};
```

structure and returns address of a new page. The last goal of the `initialize_identity_maps` function is to initialize `pgdt_buf_size` and `pgt_buf_offset`. As we are only in initialization phase, the `initialze_identity_maps` function sets `pgt_buf_offset` to zero:

```C
pgt_data.pgt_buf_offset = 0;
```

and the `pgt_data.pgt_buf_size` will be set to `77824` or `69632` depends on which boot protocol will be used by bootloader (64-bit or 32-bit). The same is for `pgt_data.pgt_buf`. If a bootloader loaded the kernel at `startup_32`, the `pgdt_data.pgdt_buf` will point to the end of the page table which already was initialzed in the [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/head_64.S):

```C
pgt_data.pgt_buf = _pgtable + BOOT_INIT_PGT_SIZE;
```

where `_pgtable` points to the beginning of this page table [_pgtable](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/vmlinux.lds.S). In other way, if a bootloader have used 64-bit boot protocol and loaded the kernel at `startup_64`, early page tables should be built by bootloader itself and `_pgtable` will be just overwrote:

```C
pgt_data.pgt_buf = _pgtable
```

As the buffer for new page tables is initialized, we may return back to the `choose_random_location` function.

Avoid reserved memory ranges
--------------------------------------------------------------------------------

After the stuff related to identity page tables is initilized, we may start to choose random location where to put decompressed kernel image. But as you may guess, we can't choose any address. There are some reseved addresses in memory ranges. Such addresses occupied by important things, like [initrd](https://en.wikipedia.org/wiki/Initial_ramdisk), kernel command line and etc. The

```C
mem_avoid_init(input, input_size, *output);
```

function will help us to do this. All non-safe memory regions will be collected in the:

```C
struct mem_vector {
	unsigned long long start;
	unsigned long long size;
};

static struct mem_vector mem_avoid[MEM_AVOID_MAX];
```

array. Where `MEM_AVOID_MAX` is from `mem_avoid_index` [enum](https://en.wikipedia.org/wiki/Enumerated_type#C) which represents different types of reserved memory regions:

```C
enum mem_avoid_index {
	MEM_AVOID_ZO_RANGE = 0,
	MEM_AVOID_INITRD,
	MEM_AVOID_CMDLINE,
	MEM_AVOID_BOOTPARAMS,
	MEM_AVOID_MEMMAP_BEGIN,
	MEM_AVOID_MEMMAP_END = MEM_AVOID_MEMMAP_BEGIN + MAX_MEMMAP_REGIONS - 1,
	MEM_AVOID_MAX,
};
```

Both are defined in the [arch/x86/boot/compressed/kaslr.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/kaslr.c) source code file.

Let's look at the implementation of the `mem_avoid_init` function. The main goal of this function is to store information about reseved memory regions described by the `mem_avoid_index` enum in the `mem_avoid` array and create new pages for such regions in our new identity mapped buffer. Numerous parts fo the `mem_avoid_index` function are similar, but let's take a look at the one of them:

```C
mem_avoid[MEM_AVOID_ZO_RANGE].start = input;
mem_avoid[MEM_AVOID_ZO_RANGE].size = (output + init_size) - input;
add_identity_map(mem_avoid[MEM_AVOID_ZO_RANGE].start,
		 mem_avoid[MEM_AVOID_ZO_RANGE].size);
```

At the beginning of the `mem_avoid_init` function tries to avoid memory region that is used for current kernel decompression. We fill an entry from the `mem_avoid` array with the start and size of such region and call the `add_identity_map` function which should build identity mapped pages for this region. The `add_identity_map` function is defined in the [arch/x86/boot/compressed/kaslr_64.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/kaslr_64.c) source code file and looks:

```C
void add_identity_map(unsigned long start, unsigned long size)
{
	unsigned long end = start + size;

	start = round_down(start, PMD_SIZE);
	end = round_up(end, PMD_SIZE);
	if (start >= end)
		return;

	kernel_ident_mapping_init(&mapping_info, (pgd_t *)top_level_pgt,
				  start, end);
}
```

As you may see it aligns memory region to 2 megabytes boundary and checks given start and end addresses.

In the end it just calls the `kernel_ident_mapping_init` function from the [arch/x86/mm/ident_map.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/mm/ident_map.c) source code file and pass `mapping_info` instance that was initilized above, address of the top level page table and addresses of memory region for which new identity mapping should be built.

The `kernel_ident_mapping_init` function sets default flags for new pages if they were not given:

```C
if (!info->kernpg_flag)
	info->kernpg_flag = _KERNPG_TABLE;
```

and starts to build new 2-megabytes (because of `PSE` bit in the `mapping_info.page_flag`) page entries (`PGD -> P4D -> PUD -> PMD` in a case of [five-level page tables](https://lwn.net/Articles/717293/) or `PGD -> PUD -> PMD` in a case of [four-level page tables](https://lwn.net/Articles/117749/)) related to the given addresses.

```C
for (; addr < end; addr = next) {
	p4d_t *p4d;

	next = (addr & PGDIR_MASK) + PGDIR_SIZE;
	if (next > end)
		next = end;

    p4d = (p4d_t *)info->alloc_pgt_page(info->context);
	result = ident_p4d_init(info, p4d, addr, next);

    return result;
}
```

First of all here we find next entry of the `Page Global Directory` for the given address and if it is greater than `end` of the given memory region, we set it to `end`. After this we allocate a new page with our `x86_mapping_info` callback that we already considered above and call the `ident_p4d_init` function. The `ident_p4d_init` function will do the same, but for low-level page directories (`p4d` -> `pud` -> `pmd`).

That's all.

New page entries related to reserved addresses are in our page tables. This is not the end of the `mem_avoid_init` function, but other parts are similar. It just build pages for [initrd](https://en.wikipedia.org/wiki/Initial_ramdisk), kernel command line and etc.

Now we may return back to `choose_random_location` function.

Physical address randomization
--------------------------------------------------------------------------------

After the reserved memory regions were stored in the `mem_avoid` array and identity mapping pages were built for them, we select minimal available address to choose random memory region to decompress the kernel:

```C
min_addr = min(*output, 512UL << 20);
```

As you may see it should be smaller than `512` megabytes. This `512` megabytes value was selected just to avoid unknown things in lower memory.

The next step is to select random physical and virtual addresses to load kernel. The first is physical addresses:

```C
random_addr = find_random_phys_addr(min_addr, output_size);
```

The `find_random_phys_addr` function is defined in the [same](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/compressed/kaslr.c) source code file:

```
static unsigned long find_random_phys_addr(unsigned long minimum,
                                           unsigned long image_size)
{
	minimum = ALIGN(minimum, CONFIG_PHYSICAL_ALIGN);

	if (process_efi_entries(minimum, image_size))
		return slots_fetch_random();

	process_e820_entries(minimum, image_size);
	return slots_fetch_random();
}
```

The main goal of `process_efi_entries` function is to find all suitable memory ranges in full accessible memory to load kernel. If the kernel compiled and runned on the system without [EFI](https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface) support, we continue to search such memory regions in the [e820](https://en.wikipedia.org/wiki/E820) regions. All founded memory regions will be stored in the

```C
struct slot_area {
	unsigned long addr;
	int num;
};

#define MAX_SLOT_AREA 100

static struct slot_area slot_areas[MAX_SLOT_AREA];
```

array. The kernel will select a random index of this array for kernel to be decompressed. This selection will be executed by the `slots_fetch_random` function. The main goal of the `slots_fetch_random` function is to select random memory range from the `slot_areas` array via `kaslr_get_random_long` function:

```C
slot = kaslr_get_random_long("Physical") % slot_max;
```

The `kaslr_get_random_long` function is defined in the [arch/x86/lib/kaslr.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/lib/kaslr.c) source code file and it just returns random number. Note that the random number will be get via different ways depends on kernel configuration and system opportunities (select random number base on [time stamp counter](https://en.wikipedia.org/wiki/Time_Stamp_Counter), [rdrand](https://en.wikipedia.org/wiki/RdRand) and so on).

That's all from this point random memory range will be selected.

Virtual address randomization
--------------------------------------------------------------------------------

After random memory region was selected by the kernel decompressor, new identity mapped pages will be built for this region by demand:

```C
random_addr = find_random_phys_addr(min_addr, output_size);

if (*output != random_addr) {
		add_identity_map(random_addr, output_size);
		*output = random_addr;
}
```

From this time `output` will store the base address of a memory region where kernel will be decompressed. But for this moment, as you may remember we randomized only physical address. Virtual address should be randomized too in a case of [x86_64](https://en.wikipedia.org/wiki/X86-64) architecture:

```C
if (IS_ENABLED(CONFIG_X86_64))
	random_addr = find_random_virt_addr(LOAD_PHYSICAL_ADDR, output_size);

*virt_addr = random_addr;
```

As you may see in a case of non `x86_64` architecture, randomzed virtual address will coincide with randomized physical address. The `find_random_virt_addr` function calculates amount of virtual memory ranges that may hold kernel image and calls the `kaslr_get_random_long` that we already saw in a previous case when we tried to find random `physical` address.

From this moment we have both randomized base physical (`*output`) and virtual (`*virt_addr`) addresses for decompressed kernel.

That's all.

Conclusion
--------------------------------------------------------------------------------

This is the end of the sixth and the last part about linux kernel booting process. We will not see posts about kernel booting anymore (maybe updates to this and previous posts), but there will be many posts about other kernel internals.

Next chapter will be about kernel initialization and we will see the first steps in the Linux kernel initialization code.

If you have any questions or suggestions write me a comment or ping me in [twitter](https://twitter.com/0xAX).

**Please note that English is not my first language, And I am really sorry for any inconvenience. If you find any mistakes please send me PR to [linux-insides](https://github.com/0xAX/linux-internals).**

Links
--------------------------------------------------------------------------------

* [Address space layout randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
* [Linux kernel boot protocol](https://github.com/torvalds/linux/blob/v4.16/Documentation/x86/boot.txt)
* [long mode](https://en.wikipedia.org/wiki/Long_mode)
* [initrd](https://en.wikipedia.org/wiki/Initial_ramdisk)
* [Enumerated type](https://en.wikipedia.org/wiki/Enumerated_type#C)
* [four-level page tables](https://lwn.net/Articles/117749/)
* [five-level page tables](https://lwn.net/Articles/717293/)
* [EFI](https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface)
* [e820](https://en.wikipedia.org/wiki/E820)
* [time stamp counter](https://en.wikipedia.org/wiki/Time_Stamp_Counter)
* [rdrand](https://en.wikipedia.org/wiki/RdRand)
* [x86_64](https://en.wikipedia.org/wiki/X86-64)
* [Previous part](linux-bootstrap-5.md)
