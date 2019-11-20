커널 초기화. Part 8.
================================================================================

스케쥴러 초기화
================================================================================

이것은 Linux 커널 초기화 프로세스 장의 여덟 번째 [파트](https://0xax.gitbooks.io/linux-insides/content/Initialization/index.html)이며 [이전 파트](https://github.com/0xAX/linux-insides/blob/master/Initialization/linux-initialization-7.md)에선 `setup_nr_cpu_ids` 함수에서 멈췄었습니다. 

이번 파트의 주요 요점은 [스케쥴러](http://en.wikipedia.org/wiki/Scheduling_%28computing%29) 초기화입니다. 그러나 스케줄러의 초기화 프로세스를 배우기 전에 몇 가지가 필요합니다. [init/main.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/init/main.c)에서 다음 단계는`setup_per_cpu_areas` 함수입니다. 이 함수는 `percpu` 변수를 위한 메모리 구역을 설정합니다. 자세한 내용은 특별히 [Per-CPU variables](https://0xax.gitbooks.io/linux-insides/content/Concepts/linux-cpu-1.html)에 대한 파트에서 읽을 수 있습니다. `percpu` 영역이 가동되어 실행되기 시작하면 다음 단계는`smp_prepare_boot_cpu` 함수입니다.

이 함수는 [symmetric multiprocessing](http://en.wikipedia.org/wiki/Symmetric_multiprocessing)을 위한 몇가지 준비를합니다. 이 함수는 각 아키텍처에 따라 맞춰져있으므로, [arch/x86/include/asm/smp.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/smp.h#L78) Linux 커널 헤더 파일에 있습니다. 이 함수의 정의를 살펴봅시다 :

```C
static inline void smp_prepare_boot_cpu(void)
{
         smp_ops.smp_prepare_boot_cpu();
}
```

여기서는`smp_ops` 구조체의`smp_prepare_boot_cpu` 콜백을 호출하는 것을 볼 수 있습니다. [arch/x86/kernel/smp.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/smp.c) 소스 코드 파일에서 이 구조체의 인스턴스의 정의를 보면 `smp_prepare_boot_cpu`가 `native_smp_prepare_boot_cpu` 함수의 호출로 확장됨을 알 수 있습니다.

```C
struct smp_ops smp_ops = {
    ...
    ...
    ...
    smp_prepare_boot_cpu = native_smp_prepare_boot_cpu,
    ...
    ...
    ...
}
EXPORT_SYMBOL_GPL(smp_ops);
```

`native_smp_prepare_boot_cpu` 함수의 생김새는 다음과 같습니다:

```C
void __init native_smp_prepare_boot_cpu(void)
{
        int me = smp_processor_id();
        switch_to_new_gdt(me);
        cpumask_set_cpu(me, cpu_callout_mask);
        per_cpu(cpu_state, me) = CPU_ONLINE;
}
```

그리고 이 함수는 다음과 같은 것들을 실행합니다 : 우선`smp_processor_id` 함수를 사용하여 현재 CPU의 `id` (부트스트랩 프로세서이고 이 순간에 `id`는 0) 를 얻습니다. 이미 [Kernel entry point](https://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-4.html)파트에서 보았기 때문에 `smp_processor_id`가 어떻게 작동하는지는 설명하지 않겠습니다. 프로세서`id` 번호를 얻은 후에는 `switch_to_new_gdt` 함수를 사용하여 주어진 CPU에 대해 [Global Descriptor Table](http://en.wikipedia.org/wiki/Global_Descriptor_Table)을 다시 로드합니다 :

```C
void switch_to_new_gdt(int cpu)
{
        struct desc_ptr gdt_descr;

        gdt_descr.address = (long)get_cpu_gdt_table(cpu);
        gdt_descr.size = GDT_SIZE - 1;
        load_gdt(&gdt_descr);
        load_percpu_segment(cpu);
}
```

`gdt_descr` 변수는 여기서 `GDT` 디스크립터에 대한 포인터를 나타냅니다 (이미 [Early interrupt and exception handling](https://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-2.html) 부분에서`desc_ptr` 구조체의 정의를 보았습니다). 우리는 주어진`id`를 가진 `CPU`에 대한 `GDT` 디스크립터의 주소와 크기를 얻습니다. `GDT_SIZE`는`256`이거나:

```C
#define GDT_SIZE (GDT_ENTRIES * 8)
```

이며, `get_cpu_gdt_table`을 통해 얻을 수있는 서술자의 주소는 :

```C
static inline struct desc_struct *get_cpu_gdt_table(unsigned int cpu)
{
        return per_cpu(gdt_page, cpu).gdt;
}
```

`get_cpu_gdt_table`은 주어진 CPU 번호에 대한 `gdt_page` percpu 변수의 값을 얻기 위해 `per_cpu` 매크로를 사용합니다. (이 경우에는 `id` -0 인 부트스트랩 프로세서)

다음과 같은 의문이 생길 수도 있습니다: 그래서 만약 우리가`gdt_page` percpu 변수에 접근 할 수 있다면, 어디에 정의되어 있나요? 사실 우리는 이미 이 책에서 그것을 보았습니다. 이 장의 첫 번째 [파트](https://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-1.html)를 읽었다면 [arch/x86/kernel/head_64.S](https://github.com/0xAX/linux/blob/0a07b238e5f488b459b6113a62e06b6aab017f71/arch/x86/kernel/head_64.S)에서 `gdt_page`의 정의를 보았던 것을 기억할 것입니다 :

```assembly
early_gdt_descr:
	.word	GDT_ENTRIES*8-1
early_gdt_descr_base:
	.quad	INIT_PER_CPU_VAR(gdt_page)
```

또한 [링커](https://github.com/0xAX/linux/blob/0a07b238e5f488b459b6113a62e06b6aab017f71/arch/x86/kernel/vmlinux.lds.S) 파일을 살펴보면`__per_cpu_load `기호다음에 위치한 것을 볼 수 있습니다 :

```C
#define INIT_PER_CPU(x) init_per_cpu__##x = x + __per_cpu_load
INIT_PER_CPU(gdt_page);
```

[arch/x86/kernel/cpu/common.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/cpu/common.c#L94)에서`gdt_page`를 채웠습니다 :

```C
DEFINE_PER_CPU_PAGE_ALIGNED(struct gdt_page, gdt_page) = { .gdt = {
#ifdef CONFIG_X86_64
	[GDT_ENTRY_KERNEL32_CS]		= GDT_ENTRY_INIT(0xc09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_CS]		= GDT_ENTRY_INIT(0xa09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_DS]		= GDT_ENTRY_INIT(0xc093, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER32_CS]	= GDT_ENTRY_INIT(0xc0fb, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER_DS]	= GDT_ENTRY_INIT(0xc0f3, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER_CS]	= GDT_ENTRY_INIT(0xa0fb, 0, 0xfffff),
    ...
    ...
    ...
```

`percpu` 변수에 대한 자세한 내용은 [Per-CPU variables](https://0xax.gitbooks.io/linux-insides/content/Concepts/linux-cpu-1.html) 파트를 참고해주세요. `GDT` 디스크립터의 주소와 크기를 얻었으므로 `load_gdt`로 `GDT`를 다시 로드합니다. `load_gdt`는 단지 `lgdt` 명령을 실행하고 다음 함수를 사용하여 `percpu_segment`를 로드하는 함수입니다:

```C
void load_percpu_segment(int cpu) {
    loadsegment(gs, 0);
    wrmsrl(MSR_GS_BASE, (unsigned long)per_cpu(irq_stack_union.gs_base, cpu));
    load_stack_canary_segment();
}
```

`percpu` 영역의 베이스 주소는 `gs`레지스터 (또는 `x86`의 경우 `fs`레지스터)를 포함해야하므로 우리는 `loadsegment` 매크로를 사용하고 `gs`를 전달합니다. 다음 단계에서 [IRQ](http://en.wikipedia.org/wiki/Interrupt_request_%28PC_architecture%29) 스택 및 설정 스택이 [canary](http://en.wikipedia.org/wiki/Buffer_overflow_protection)인 경우 베이스 주소를 작성합니다. (`x86_32`에만 해당) 새로운`GDT`를 로드 한 후에는, 현재 CPU로 `cpu_callout_mask` 비트맵을 채우고 `cpu_state` percpu 변수를 현재 프로세서에 대한 값-`CPU_ONLINE`-으로 설정해 cpu 상태를 온라인으로 설정합니다 :

```C
cpumask_set_cpu(me, cpu_callout_mask);
per_cpu(cpu_state, me) = CPU_ONLINE;
```

그래서 `cpu_callout_mask`비트 맵은 뭘까요... 부트스트랩 프로세서 (x86에서 첫 번째로 부팅되는 프로세서)를 초기화함에 따라 멀티프로세서 시스템의 다른 프로세서들은 '보조 프로세서'(secondary processors)라고합니다. 리눅스 커널은 다음 두 비트 마스크를 사용합니다.

* `cpu_callout_mask`
* `cpu_callin_mask`

부트 스트랩 프로세서가 초기화되면 커널은 `cpu_callout_mask`를 업데이트하여 다음으로 초기화 할 수 있는 보조 프로세서를 나타냅니다. All other or secondary processors can do some initialization stuff before and check the `cpu_callout_mask` on the boostrap processor bit. 다른 모든 프로세서나 몇개의 보조 프로세서들도 초기화 작업을 수행한 후 `cpu_callout_mask`의 부트스트랩 프로세서 비트를 체크할 수 있습니다. 부트스트랩 프로세서가 이 보조 프로세서로 `cpu_callout_mask`를 채운 후에만 나머지 초기화가 계속됩니다. 특정 프로세서가 초기화 과정을 마치면 해당 프로세서는`cpu_callin_mask`의 비트를 설정합니다. 부트스트랩 프로세서가 현재 보조 프로세서에 해당하는 비트를 `cpu_callin_mask`에서 찾으면 이 프로세서는 나머지 보조 프로세서 중 하나의 초기화를 위해 동일한 절차를 반복합니다. 간단히 설명하여 여태까지 말한대로 작동하지만 좀더 자세한 내용은 `SMP` 챕터에서  살펴보도록 하겠습니다.
        
이것이 끝입니다. 우리는 `SMP` 부팅 준비를 모두 마쳤습니다.

존리스트(zonelist) 구축
-----------------------------------------------------------------------

다음 단계에서는`build_all_zonelists` 함수의 호출을 볼 수 있습니다. 이 함수는 할당이 선호되는대로 구역의 순서를 설정합니다. 구역이란 무엇이며 순서는 무엇인지는 곧 이해하게 될 것입니다. 우선은 리눅스 커널이 물리적 메모리를 어떻게 여기는지 봅시다. 물리적 메모리는 '노드'(`nodes`)라고 불리는 덩어리로 나뉩니다. `NUMA`에 대한 하드웨어 지원이없는 경우 하나의 노드만 보일 것입니다.

```
$ cat /sys/devices/system/node/node0/numastat 
numa_hit 72452442
numa_miss 0
numa_foreign 0
interleave_hit 12925
local_node 72452442
other_node 0
```

모든 `node`는 리눅스 커널에서 `struct pglist_data`로 표시됩니다. 각 노드는 '구역'(`zones`)이라고 불리는 여러 개의 특수한 블록으로 나뉩니다. 모든 구역은 리눅스 커널에서`zone struct`로 표시되며 다음 중 하나의 유형입니다.

* `ZONE_DMA` - 0-16M;
* `ZONE_DMA32` - 4G 미만의 영역(area)만  DMA를 수행 할 수있는 32 비트 장치에 사용됨;
* `ZONE_NORMAL` - `x86_64`에서 4GB부터의 모든 RAM;
* `ZONE_HIGHMEM` - `x86_64`에서 존재하지 않음;
* `ZONE_MOVABLE` - 움직일 수 있는(moveable) 페이지를 포함하는 zone.

이것들은 `zone_type` 열거형으로 표시됩니다. 다음을 통해 zone에 대한 정보를 얻을 수 있습니다.

```
$ cat /proc/zoneinfo
Node 0, zone      DMA
  pages free     3975
        min      3
        low      3
        ...
        ...
Node 0, zone    DMA32
  pages free     694163
        min      875
        low      1093
        ...
        ...
Node 0, zone   Normal
  pages free     2529995
        min      3146
        low      3932
        ...
        ...
```

위에 적힌 것과 같이 모든 노드는 메모리의 `pglist_data` 또는 `pg_data_t` 구조체로 기술됩니다. 이 구조체는 [include / linux / mmzone.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/mmzone.h)에 정의되어 있습니다. [mm/page_alloc.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/mm/page_alloc.c)의 `build_all_zonelists` 함수는 정렬된 (각 zone의 `DMA` ,`DMA32`,`NORMAL`,`HIGH_MEMORY`,`MOVABLE`에 대한)`zonelist`를 구성합니다. 이것은 선택된 `zone` 또는 `node`가 할당 요청을 충족시킬 수 없을 때 방문 할 zone/노드를 지정합니다. 이게 전부입니다. `NUMA` 및 멀티프로세서 시스템에 대한 자세한 내용은 특별 파트에 있습니다.

스케줄러 초기화 전의 나머지 것들
--------------------------------------------------------------------------------

리눅스 커널 스케줄러 초기화 프로세스를 시작하기 전에 몇 가지 작업이 필요합니다. 첫 번째는 [mm/page_alloc.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/mm/page_alloc.c)의 `page_alloc_init` 함수입니다  이 함수는 꽤 쉽습니다.

```C
void __init page_alloc_init(void)
{
    int ret;
 
    ret = cpuhp_setup_state_nocalls(CPUHP_PAGE_ALLOC_DEAD,
                                    "mm/page_alloc:dead", NULL,
                                    page_alloc_cpu_dead);
    WARN_ON(ret < 0);
}
```

이 함수는 `CPUHP_PAGE_ALLOC_DEAD` cpu [hotplug](https://www.kernel.org/doc/Documentation/cpu-hotplug.txt) 상태에 대한`startup` 및 `teardown` 콜백 (두 번째 및 세 번째 매개 변수)을 설정합니다. 물론 이 함수의 구현은 `CONFIG_HOTPLUG_CPU` 커널 설정 옵션에 따라 달라지며 이 옵션을 설정하면 `hotplug` 상태에 따라 시스템의 모든 CPU에 대해 이러한 콜백이 설정됩니다. [hotplug](https://www.kernel.org/doc/Documentation/cpu-hotplug.txt) 메커니즘은 너무 큰 주제이므로이 책에서는 설명하지 않겠습니다.

이 함수 후에 초기화 출력에서 커널 명령 행을 볼 수 있습니다.

![kernel command line](http://oi58.tinypic.com/2m7vz10.jpg)

그리고 리눅스 커널 커맨드 라인을 처리하는 `parse_early_param` 및 `parse_args`와 같은 몇 가지 기능이 있습니다. 우리는 이미 커널 초기화 챕터의 여섯 번째 [파트](https://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-6.html)에서 `parse_early_param` 함수의 호출을 보았을 것입니다. 그런데 왜 다시 호출할까요? 답은 간단합니다:  (우리의 경우`x86_64`) 특정 아키텍처를 위한 (architecture-specific) 코드에서 이 함수를 호출했어도 모든 아키텍처가 이 함수를 호출하는 것은 아니기 때문입니다. 비-초기(non-early) 명령 줄 인수(argument)들을 분석(parse)하고 처리하려면 두 번째 함수 인 `parse_args`를 호출해야합니다.

다음 단계에서 [kernel / jump_label.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/kernel/jump_label.c) 내의 `jump_label_init`의 호출을 볼 수 있습니다. [jump label](https://lwn.net/Articles/412072/)을 초기화합니다.

그 후에 우리는 [printk](http://www.makelinux.net/books/lkd2/ch18lev1sec3) 로그 버퍼를 설정하는`setup_log_buf` 함수의 호출을 볼 수 있습니다. 우리는 이미 이 함수를 리눅스 커널 초기화 프로세스 챕터의 일곱 번째 [파트](https://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-7.html)에서 보았습니다.

PID 해시 초기화
--------------------------------------------------------------------------------

다음은`pidhash_init` 함수입니다. 아시다시피 각 프로세스에는 '프로세스 식별 번호'(`process identification number`) 또는 `PID`라고 불리는 고유 번호가 할당되어 있습니다. 포크 또는 클론으로 생성 된 각 프로세스에는 커널에 의해 새로운 고유  `PID`값이 자동으로 할당됩니다. `PID`의 관리는 `struct pid`와`struct upid`라는 두 가지의 특별한 자료구조를 중심으로 이루집니다. 첫 번째 자료구조는 커널의 `PID`에 대한 정보를 나타냅니다. 두 번째 자료구조는 특정 네임 스페이스에서 볼 수있는 정보를 나타냅니다. 특수 해시 테이블에 저장된 모든`PID` 인스턴스는:

```C
static struct hlist_head *pid_hash;
```

이 해시 테이블은 `PID` 숫자값에 해당하는 pid 인스턴스를 찾는 데 사용됩니다. 따라서 `pidhash_init`는이 해시 테이블을 초기화합니다. `pidhash_init` 함수의 시작에서 우리는`alloc_large_system_hash`의 호출을 볼 수 있습니다 :

```C
pid_hash = alloc_large_system_hash("PID", sizeof(*pid_hash), 0, 18,
                                   HASH_EARLY | HASH_SMALL,
                                   &pidhash_shift, NULL,
                                   0, 4096);
```

`pid_hash`의 요소 수는`RAM` 구성에 따라 다르지만`2 ^ 4`와`2 ^ 12` 사이입니다. `pidhash_init`는 크기를 계산하고 필요한 저장공간(이 경우`hlist`임 - [doubly linked list](https://0xax.gitbooks.io/linux-insides/content/DataStructures/linux-datastructures-1.html)와 동일함)을 할당하지만 대신 [struct hlist_head](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/types.h)에 포인터를 하나 포함합니다. `alloc_large_system_hash` 함수는 만약 우리가 `HASH_EARLY` 플래그를 전달한다면  `meakblock_virt_alloc_nopanic`와 함께 큰 시스템 해시 테이블(large system hash table)을 할당하고, 플래그를 전달하지 않으면 `__vmalloc`과 함께 할당합니다.

그 결과는`dmesg` 출력에서 확인할 수 있습니다 :

```
$ dmesg | grep hash
[    0.000000] PID hash table entries: 4096 (order: 3, 32768 bytes)
...
...
...
```

That's all. The rest of the stuff before scheduler initialization is the following functions: `vfs_caches_init_early` does early initialization of the [virtual file system](http://en.wikipedia.org/wiki/Virtual_file_system) (more about it will be in the chapter which will describe virtual file system), `sort_main_extable` sorts the kernel's built-in exception table entries which are between `__start___ex_table` and `__stop___ex_table`, and `trap_init` initializes trap handlers (more about last two function we will know in the separate chapter about interrupts).

The last step before the scheduler initialization is initialization of the memory manager with the `mm_init` function from the [init/main.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/init/main.c). As we can see, the `mm_init` function initializes different parts of the linux kernel memory manager:

```C
page_ext_init_flatmem();
mem_init();
kmem_cache_init();
percpu_init_late();
pgtable_init();
vmalloc_init();
```

The first is `page_ext_init_flatmem` which depends on the `CONFIG_SPARSEMEM` kernel configuration option and initializes extended data per page handling. The `mem_init` releases all `bootmem`, the `kmem_cache_init` initializes kernel cache, the `percpu_init_late` - replaces `percpu` chunks with those allocated by [slub](http://en.wikipedia.org/wiki/SLUB_%28software%29), the `pgtable_init` - initializes the `page->ptl` kernel cache, the `vmalloc_init` - initializes `vmalloc`. Please, **NOTE** that we will not dive into details about all of these functions and concepts, but we will see all of they it in the [Linux kernel memory manager](https://0xax.gitbooks.io/linux-insides/content/MM/index.html) chapter.

That's all. Now we can look on the `scheduler`.

Scheduler initialization
--------------------------------------------------------------------------------

And now we come to the main purpose of this part - initialization of the task scheduler. I want to say again as I already did it many times, you will not see the full explanation of the scheduler here, there will be special separate chapter about this. Here will be described first initial scheduler mechanisms which are initialized first of all. So let's start.

Our current point is the `sched_init` function from the [kernel/sched/core.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/kernel/sched/core.c) kernel source code file and as we can understand from the function's name, it initializes scheduler. Let's start to dive into this function and try to understand how the scheduler is initialized. At the start of the `sched_init` function we can see the following call:

```C
sched_clock_init();
```

The `sched_clock_init` is pretty easy function and as we may see it just sets `sched_clock_init` variable:

```C
void sched_clock_init(void)
{
	sched_clock_running = 1;
}
```

that will be used later. At the next step is initialization of the array of `waitqueues`:

```C
for (i = 0; i < WAIT_TABLE_SIZE; i++)
	init_waitqueue_head(bit_wait_table + i);
```

where `bit_wait_table` is defined as:

```C
#define WAIT_TABLE_BITS 8
#define WAIT_TABLE_SIZE (1 << WAIT_TABLE_BITS)
static wait_queue_head_t bit_wait_table[WAIT_TABLE_SIZE] __cacheline_aligned;
```

The `bit_wait_table` is array of wait queues that will be used for wait/wake up of processes depends on the value of a designated bit. The next step after initialization of `waitqueues` array is calculating size of memory to allocate for the `root_task_group`. As we may see this size depends on two following kernel configuration options:

```C
#ifdef CONFIG_FAIR_GROUP_SCHED
         alloc_size += 2 * nr_cpu_ids * sizeof(void **);
#endif
#ifdef CONFIG_RT_GROUP_SCHED
         alloc_size += 2 * nr_cpu_ids * sizeof(void **);
#endif
```

* `CONFIG_FAIR_GROUP_SCHED`;
* `CONFIG_RT_GROUP_SCHED`.

Both of these options provide two different planning models. As we can read from the [documentation](https://www.kernel.org/doc/Documentation/scheduler/sched-design-CFS.txt), the current scheduler - `CFS` or `Completely Fair Scheduler` use a simple concept. It models process scheduling as if the system has an ideal multitasking processor where each process would receive `1/n` processor time, where `n` is the number of the runnable processes. The scheduler uses the special set of rules. These rules determine when and how to select a new process to run and they are called `scheduling policy`.

The `Completely Fair Scheduler` supports following `normal` or in other words `non-real-time` scheduling policies:

* `SCHED_NORMAL`;
* `SCHED_BATCH`;
* `SCHED_IDLE`.

The `SCHED_NORMAL` is used for the most normal applications, the amount of cpu each process consumes is mostly determined by the [nice](http://en.wikipedia.org/wiki/Nice_%28Unix%29) value, the `SCHED_BATCH` used for the 100% non-interactive tasks and the `SCHED_IDLE` runs tasks only when the processor has no task to run besides this task.

The `real-time` policies are also supported for the time-critical applications: `SCHED_FIFO` and `SCHED_RR`. If you've read something about the Linux kernel scheduler, you can know that it is modular. It means that it supports different algorithms to schedule different types of processes. Usually this modularity is called `scheduler classes`. These modules encapsulate scheduling policy details and are handled by the scheduler core without knowing too much about them. 

Now let's get back to the our code and look on the two configuration options: `CONFIG_FAIR_GROUP_SCHED` and `CONFIG_RT_GROUP_SCHED`. The least unit which scheduler operates is an individual task or thread. But a process is not only one type of entities of which the scheduler may operate. Both of these options provides support for group scheduling. The first one option provides support for group scheduling with `completely fair scheduler` policies and the second with `real-time` policies respectively.

In simple words, group scheduling is a feature that allows us to schedule a set of tasks as if a single task. For example, if you create a group with two tasks on the group, then this group is just like one normal task, from the kernel perspective. After a group is scheduled, the scheduler will pick a task from this group and it will be scheduled inside the group. So, such mechanism allows us to build hierarchies and manage their resources. Although a minimal unit of scheduling is a process, the Linux kernel scheduler does not use `task_struct` structure under the hood. There is special `sched_entity` structure that is used by the Linux kernel scheduler as scheduling unit.

So, the current goal is to calculate a space to allocate for a `sched_entity(ies)` of the root task group and we do it two times with:

```C
#ifdef CONFIG_FAIR_GROUP_SCHED
         alloc_size += 2 * nr_cpu_ids * sizeof(void **);
#endif
#ifdef CONFIG_RT_GROUP_SCHED
         alloc_size += 2 * nr_cpu_ids * sizeof(void **);
#endif
```

The first is for case when scheduling of task groups is enabled with `completely fair` scheduler and the second is for the same purpose by in a case of `real-time` scheduler. So here we calculate size which is equal to size of a pointer multiplied on amount of CPUs in the system and multiplied to `2`. We need to multiply this on `2` as we will need to allocate a space for two things:

* scheduler entity structure;
* `runqueue`.

After we have calculated size, we allocate a space with the `kzalloc` function and set pointers of `sched_entity` and `runquques` there:

```C
ptr = (unsigned long)kzalloc(alloc_size, GFP_NOWAIT);
 
#ifdef CONFIG_FAIR_GROUP_SCHED
        root_task_group.se = (struct sched_entity **)ptr;
        ptr += nr_cpu_ids * sizeof(void **);

        root_task_group.cfs_rq = (struct cfs_rq **)ptr;
        ptr += nr_cpu_ids * sizeof(void **);
#endif
#ifdef CONFIG_RT_GROUP_SCHED
		root_task_group.rt_se = (struct sched_rt_entity **)ptr;
		ptr += nr_cpu_ids * sizeof(void **);

		root_task_group.rt_rq = (struct rt_rq **)ptr;
		ptr += nr_cpu_ids * sizeof(void **);

#endif
```

As I already mentioned, the Linux group scheduling mechanism allows to specify a hierarchy. The root of such hierarchies is the `root_runqueuetask_group` task group structure. This structure contains many fields, but we are interested in `se`, `rt_se`, `cfs_rq` and `rt_rq` for this moment:

The first two are instances of `sched_entity` structure. It is defined in the [include/linux/sched.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/sched.h) kernel header filed and used by the scheduler as a unit of scheduling.

```C
struct task_group {
    ...
    ...
    struct sched_entity **se;
    struct cfs_rq **cfs_rq;
    ...
    ...
}
```

The `cfs_rq` and `rt_rq` present `run queues`. A `run queue` is a special `per-cpu` structure that is used by the Linux kernel scheduler to store `active` threads or in other words set of threads which potentially will be picked up by the scheduler to run.

The space is allocated and the next step is to initialize a `bandwidth` of CPU for `real-time` and `deadline` tasks:

```C
init_rt_bandwidth(&def_rt_bandwidth,
                  global_rt_period(), global_rt_runtime());
init_dl_bandwidth(&def_dl_bandwidth,
                  global_rt_period(), global_rt_runtime());
```

All groups have to be able to rely on the amount of CPU time. The two following structures: `def_rt_bandwidth` and `def_dl_bandwidth` represent default values of bandwidths for `real-time` and `deadline` tasks. We will not look at definition of these structures as it is not so important for now, but we are interested in two following values:

* `sched_rt_period_us`;
* `sched_rt_runtime_us`.

The first represents a period and the second represents quantum that is allocated for `real-time` tasks during `sched_rt_period_us`. You may see global values of these parameters in the:

```
$ cat /proc/sys/kernel/sched_rt_period_us 
1000000

$ cat /proc/sys/kernel/sched_rt_runtime_us 
950000
```

The values related to a group can be configured in `<cgroup>/cpu.rt_period_us` and `<cgroup>/cpu.rt_runtime_us`. Due no one filesystem is not mounted yet, the `def_rt_bandwidth` and the `def_dl_bandwidth` will be initialzed with default values which will be retuned by the `global_rt_period` and `global_rt_runtime` functions.

That's all with the bandwiths of `real-time` and `deadline` tasks and in the next step, depends on enable of [SMP](http://en.wikipedia.org/wiki/Symmetric_multiprocessing), we make initialization of the `root domain`:

```C
#ifdef CONFIG_SMP
	init_defrootdomain();
#endif
```

The real-time scheduler requires global resources to make scheduling decision. But unfortunately scalability bottlenecks appear as the number of CPUs increase. The concept of `root domains` was introduced for improving scalability and avoid such bottlenecks. Instead of bypassing over all `run queues`, the scheduler gets information about a CPU where/from to push/pull a `real-time` task from the `root_domain` structure. This structure is defined in the [kernel/sched/sched.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/kernel/sched/sched.h) kernel header file and just keeps track of CPUs that can be used to push or pull a process.

After `root domain` initialization, we make initialization of the `bandwidth` for the `real-time` tasks of the `root task group` as we did the same above: 
```C
#ifdef CONFIG_RT_GROUP_SCHED
	init_rt_bandwidth(&root_task_group.rt_bandwidth,
			global_rt_period(), global_rt_runtime());
#endif
```

with the same default values.

In the next step, depends on the `CONFIG_CGROUP_SCHED` kernel configuration option we allocate `slab` cache for `task_group(s)` and initialize the `siblings` and `children` lists of the root task group. As we can read from the documentation, the `CONFIG_CGROUP_SCHED` is:

```
This option allows you to create arbitrary task groups using the "cgroup" pseudo
filesystem and control the cpu bandwidth allocated to each such task group.
```

As we finished with the lists initialization, we can see the call of the `autogroup_init` function:

```C
#ifdef CONFIG_CGROUP_SCHED
         list_add(&root_task_group.list, &task_groups);
         INIT_LIST_HEAD(&root_task_group.children);
         INIT_LIST_HEAD(&root_task_group.siblings);
         autogroup_init(&init_task);
#endif
```

which initializes automatic process group scheduling. The `autogroup` feature is about automatic creation and population of a new task group during creation of a new session via [setsid](https://linux.die.net/man/2/setsid) call.

After this we are going through the all `possible` CPUs (you can remember that `possible` CPUs are stored in the `cpu_possible_mask` bitmap that can ever be available in the system) and initialize a `runqueue` for each `possible` cpu:

```C
for_each_possible_cpu(i) {
    struct rq *rq;
    ...
    ...
    ...
```

The `rq` structure in the Linux kernel is defined in the [kernel/sched/sched.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/kernel/sched/sched.h#L625). As I already mentioned this above, a `run queue` is a fundamental data structure in a scheduling process. The scheduler uses it to determine who will be runned next. As you may see, this structure has many different fields and we will not cover all of them here, but we will look on them when they will be directly used.

After initialization of `per-cpu` run queues with default values, we need to setup `load weight` of the first task in the system:

```C
set_load_weight(&init_task);
```

First of all let's try to understand what is it `load weight` of a process. If you will look at the definition of the `sched_entity` structure, you will see that it starts from the `load` field:

```C
struct sched_entity {
	struct load_weight		load;
    ...
    ...
    ...
}
```

represented by the `load_weight` structure which just contains two fields that represent actual load weight of a scheduler entity and its invariant value:

```C
struct load_weight {
	unsigned long	weight;
	u32				inv_weight;
};
```

You already may know that each process in the system has `priority`. The higher priority allows to get more time to run. A `load weight` of a process is a relation between priority of this process and timeslices of this process. Each process has three following fields related to priority:

```C
struct task_struct {
...
...
...
	int				prio;
	int				static_prio;
	int				normal_prio;
...
...
...
}
```

The first one is `dynamic priority` which can't be changed during lifetime of a process based on its static priority and interactivity of the process. The `static_prio` contains initial priority most likely well-known to you `nice value`. This value does not changed by the kernel if a user will not change it. The last one is `normal_priority` based on the value of the `static_prio` too, but also it depends on the scheduling policy of a process.

So the main goal of the `set_load_weight` function is to initialze `load_weight` fields for the `init` task:

```C
static void set_load_weight(struct task_struct *p)
{
	int prio = p->static_prio - MAX_RT_PRIO;
	struct load_weight *load = &p->se.load;

	if (idle_policy(p->policy)) {
		load->weight = scale_load(WEIGHT_IDLEPRIO);
		load->inv_weight = WMULT_IDLEPRIO;
		return;
	}

	load->weight = scale_load(sched_prio_to_weight[prio]);
	load->inv_weight = sched_prio_to_wmult[prio];
}
```

As you may see we calculate initial `prio` from the initial value of the `static_prio` of the `init` task and use it as index of `sched_prio_to_weight` and `sched_prio_to_wmult` arrays to set `weight` and `inv_weight` values. These two arrays contain a `load weight` depends on priority value. In a case of when a process is `idle` process, we set minimal load weight.

For this moment we came to the end of initialization process of the Linux kernel scheduler. The last steps are: to make current process (it will be the first `init` process) `idle` that will be runned when a cpu has no other process to run. Calculating next time period of the next calculation of CPU load and initialization of the `fair` class:

```C
__init void init_sched_fair_class(void)
{
#ifdef CONFIG_SMP
	open_softirq(SCHED_SOFTIRQ, run_rebalance_domains);
#endif
}
```

Here we register a [soft irq](https://0xax.gitbooks.io/linux-insides/content/Interrupts/linux-interrupts-9.html) that will call the `run_rebalance_domains` handler. After the `SCHED_SOFTIRQ` will be triggered, the `run_rebalance` will be called to rebalance a run queue on the current CPU.

The last two steps of the `sched_init` function is to initialization of scheduler statistics and setting `scheeduler_running` variable:

```C
scheduler_running = 1;
```

That's all. Linux kernel scheduler is initialized. Of course, we have skipped many different details and explanations here, because we need to know and understand how different concepts (like process and process groups, runqueue, rcu, etc.) works in the linux kernel , but we took a short look on the scheduler initialization process. We will look all other details in the separate part which will be fully dedicated to the scheduler.

Conclusion
--------------------------------------------------------------------------------

It is the end of the eighth part about the linux kernel initialization process. In this part, we looked on the initialization process of the scheduler and we will continue in the next part to dive in the linux kernel initialization process and will see initialization of the [RCU](http://en.wikipedia.org/wiki/Read-copy-update) and many other initialization stuff in the next part.

If you have any questions or suggestions write me a comment or ping me at [twitter](https://twitter.com/0xAX).

**Please note that English is not my first language, And I am really sorry for any inconvenience. If you find any mistakes please send me PR to [linux-insides](https://github.com/0xAX/linux-insides).**

Links
--------------------------------------------------------------------------------

* [CPU masks](https://0xax.gitbooks.io/linux-insides/content/Concepts/linux-cpu-2.html)
* [high-resolution kernel timer](https://www.kernel.org/doc/Documentation/timers/hrtimers.txt)
* [spinlock](http://en.wikipedia.org/wiki/Spinlock)
* [Run queue](http://en.wikipedia.org/wiki/Run_queue)
* [Linux kernel memory manager](https://0xax.gitbooks.io/linux-insides/content/MM/index.html)
* [slub](http://en.wikipedia.org/wiki/SLUB_%28software%29)
* [virtual file system](http://en.wikipedia.org/wiki/Virtual_file_system)
* [Linux kernel hotplug documentation](https://www.kernel.org/doc/Documentation/cpu-hotplug.txt)
* [IRQ](http://en.wikipedia.org/wiki/Interrupt_request_%28PC_architecture%29)
* [Global Descriptor Table](http://en.wikipedia.org/wiki/Global_Descriptor_Table)
* [Per-CPU variables](https://0xax.gitbooks.io/linux-insides/content/Concepts/linux-cpu-1.html)
* [SMP](http://en.wikipedia.org/wiki/Symmetric_multiprocessing)
* [RCU](http://en.wikipedia.org/wiki/Read-copy-update)
* [CFS Scheduler documentation](https://www.kernel.org/doc/Documentation/scheduler/sched-design-CFS.txt)
* [Real-Time group scheduling](https://www.kernel.org/doc/Documentation/scheduler/sched-rt-group.txt)
* [Previous part](https://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-7.html)
