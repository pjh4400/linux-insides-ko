Kernel booting process. Part 3.
커널 부팅 과정. Part 3.
================================================================================

Video mode initialization and transition to protected mode
비디오 모드의 초기화와 보호 모드로 전환하기
--------------------------------------------------------------------------------

This is the third part of the `Kernel booting process` series. In the previous [part](linux-bootstrap-2.md#kernel-booting-process-part-2), we stopped right before the call to the `set_video` routine from [main.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c).
이것은 커널 부팅 과정 시리즈의 세번째 파트입니다. 이전 [파트](linux-bootstrap-2.md#kernel-booting-process-part-2)에서는 [main.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c)에서는 `set_video`루틴을 호출하기 직전에 끝났습니다. 

In this part, we will look at:
이번 파트에서 볼 것: 

* video mode initialization in the kernel setup code,
* 커널 설정 코드에서 비디오 모드 초기화하기
* the preparations made before switching into protected mode,
* 보호 모드로 전환하기 전에 준비할 것
* the transition to protected mode
* 보호 모드로 전환하기

**NOTE** If you don't know anything about protected mode, you can find some information about it in the previous [part](linux-bootstrap-2.md#protected-mode). Also, there are a couple of [links](linux-bootstrap-2.md#links) which can help you.
**참고** 보호 모드가 무엇인지 모르는 분은 이전 [파트](linux-bootstrap-2.md#protected-mode)에서 정보를 찾아볼 수 있습니다. 또한 도움을 줄 수 있는 몇 가지  [링크](linux-bootstrap-2.md#links)가 있습니다.

As I wrote above, we will start from the `set_video` function which is defined in the [arch/x86/boot/video.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/video.c) source code file. We can see that it starts by first getting the video mode from the `boot_params.hdr` structure:
소스코드파일[arch/x86/boot/video.c](https://github.com(https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/video.c)에 정의되어 있는 `set_video` 함수에서 시작합니다. 제일 먼저 `boot_params.hdr`구조에서 비디오 모드를 가져옵니다.


```C
u16 mode = boot_params.hdr.vid_mode;
```


which we filled in the `copy_boot_params` function (you can read about it in the previous post). `vid_mode` is an obligatory field which is filled by the bootloader. You can find information about it in the kernel `boot protocol`:
`copy_boot_params` 함수가 채워져 있을 것입니니다(이전 포스트 참조). 이는  `vid_mode`부트로더를 채우는데 필요한 필드입니다. `boot protocol`커널에서 이에 대한 정보를 찾을 수 있습니다.

```
Offset	Proto	Name		Meaning
/Size
01FA/2	ALL	    vid_mode	Video mode control
```

As we can read from the linux kernel boot protocol:
리눅스 커널 부트 프로토콜에서 읽을 수 있는 것처럼:

```
vga=<mode>
	<mode> here is either an integer (in C notation, either
	decimal, octal, or hexadecimal) or one of the strings
	"normal" (meaning 0xFFFF), "ext" (meaning 0xFFFE) or "ask"
	(meaning 0xFFFD).  This value should be entered into the
	vid_mode field, as it is used by the kernel before the command
	line is parsed.
```

So we can add the `vga` option to the grub (or another bootloader's) configuration file and it will pass this option to the kernel command line. This option can have different values as mentioned in the description. For example, it can be an integer number `0xFFFD` or `ask`. If you pass `ask` to `vga`, you will see a menu like this:
따라서 `vga` 옵션을 grub(또는 다른 부트로더) 구성 파일에 추가할 수 있으며, 이 옵션을 커널 커맨드 라인에 전달할 수 있습니다. 이 옵션은 설명에 언급 된대로 다른 값을 가질 수있습니다. 예를 들어 정수 `0xFFFD`이나 `ask`를 사용할 수 있습니다. `vga`에 `ask`를 전달하면 다음과 같은 메뉴가 나옵니다:

![video mode setup menu](http://oi59.tinypic.com/ejcz81.jpg)

which will ask to select a video mode. We will look at its implementation, but before diving into the implementation we have to look at some other things.
비디오 모드를 선택하라는 메시지가 표시됩니다.  구현을 살펴보기 전에 봐야하는 것들이 있습니다.

Kernel data types
커널 데이터 타입
--------------------------------------------------------------------------------

Earlier we saw definitions of different data types like `u16` etc. in the kernel setup code. Let's look at a couple of data types provided by the kernel:
이전 커널 설정 코드에서 `u16`과 같은 다른 데이터 타입의 정의를 봤습니다. 커널이 제공하는 몇가지 데이터 타입을 살펴봅시다.


| Type | char | short | int | long | u8 | u16 | u32 | u64 |
|------|------|-------|-----|------|----|-----|-----|-----|
| Size |  1   |   2   |  4  |   8  |  1 |  2  |  4  |  8  |

If you read the source code of the kernel, you'll see these very often and so it will be good to remember them.
이 커널의 소스코드들은 매우 자주 보게 될 것이니 기억하는 것이 좋습니다.

Heap API
--------------------------------------------------------------------------------

After we get `vid_mode` from `boot_params.hdr` in the `set_video` function, we can see the call to the `RESET_HEAP` function. `RESET_HEAP` is a macro which is defined in [arch/x86/boot/boot.h](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/boot.h) header file.
다음으로 `boot_params.hdr`의 `set_video`함수에서 `vid_mode`를 가져와 `RESET_HEAP` 함수를 호출하는 것을 볼 수 있습니다. `RESET_HEAP`은 [arch/x86/boot/boot.h](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/boot.h)헤더 파일에서 정의된 매크로입니다.

This macro is defined as:
이 매크로는 다음과 같이 정의됩니다:

```C
#define RESET_HEAP() ((void *)( HEAP = _end ))
```

If you have read the second part, you will remember that we initialized the heap with the [`init_heap`](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c) function. We have a couple of utility macros and functions for managing the heap which are defined in `arch/x86/boot/boot.h` header file.
두 번째 파트를 읽었다면 [`init_heap`](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c)함수를 사용해 힙이 초기화되는 것을 기억할 것입니다. `arch/x86/boot/boot.h`에 힙을 관리하기 위해 정의된 유틸리티 매크로와 함수가 있습니다.

They are:
그것들은:

```C
#define RESET_HEAP()
```

As we saw just above, it resets the heap by setting the `HEAP` variable to `_end`, where `_end` is just `extern char _end[];`
위에서 본 것처럼 `HEAP`의 `_end`변수를 설정함으로써 힙을 초기화합니다. `_end`는 `extern char _end[];에 있습니다.`


Next is the `GET_HEAP` macro:
다음은 `GET_HEAP`매크로입니다:

```C
#define GET_HEAP(type, n) \
	((type *)__get_heap(sizeof(type),__alignof__(type),(n)))
```

for heap allocation. It calls the internal function `__get_heap` with 3 parameters:
힙을 할당하기 위해 `__get_heap`에 3개의 매개변수를 넣어 내부함수를 호출합니다:

* the size of the datatype to be allocated for
* 할당할 데이터 타입의 크기
* `__alignof__(type)` specifies how variables of this type are to be aligned
* `__alignof__(type)`은 어떻게 이 유형의 변수를 정렬할 것인지
* `n` specifies how many items to allocate
* `n`은 할당할 항목의 수

The implementation of `__get_heap` is:
`__get_heap`의 구현:

```C
static inline char *__get_heap(size_t s, size_t a, size_t n)
{
	char *tmp;

	HEAP = (char *)(((size_t)HEAP+(a-1)) & ~(a-1));
	tmp = HEAP;
	HEAP += s*n;
	return tmp;
}
```

and we will further see its usage, something like:
다음과 같은 사용법을 볼 수 있습니다.

```C
saved.data = GET_HEAP(u16, saved.x * saved.y);
```

Let's try to understand how `__get_heap` works. We can see here that `HEAP` (which is equal to `_end` after `RESET_HEAP()`) is assigned the address of the aligned memory according to the `a` parameter. After this we save the memory address from `HEAP` to the `tmp` variable, move `HEAP` to the end of the allocated block and return `tmp` which is the start address of allocated memory.
`__get_heap`이 어떻게 작동하는지 이해해봅시다. `HEAP`()의 매개변수 `a`에 따라 정렬된 메모리의 주소가 할당된 것을 알 수 있습니다. 다음으로 `HEAP`에서  `tmp`변수의 메모리주소를 저장하면 `HEAP`은 할당된 블록으 끝으로 이동하고 할당된 메모리의 시작 주소에 `tmp`가 반환도비니다. 


And the last function is:
마지막 기능은 다음과 같습니다.

```C
static inline bool heap_free(size_t n)
{
	return (int)(heap_end - HEAP) >= (int)n;
}
```

which subtracts value of the `HEAP` pointer from the `heap_end` (we calculated it in the previous [part](linux-bootstrap-2.md)) and returns 1 if there is enough memory available for `n`.
(이전 [파트](linux-bootstrap-2.md)에서 계산)`heap_end`에서 `HEAP`포인터의 값을 빼고 사용할 수 있는 메모리가 충분하면 1을 반환합니다.

That's all. Now we have a simple API for heap and can setup video mode.
이제 힙에대한 간단한 API가 있으면 비디오 모드를 설정할 수 있습니다.

Set up video mode
비디오 모드 설정
--------------------------------------------------------------------------------

Now we can move directly to video mode initialization. We stopped at the `RESET_HEAP()` call in the `set_video` function. Next is the call to  `store_mode_params` which stores video mode parameters in the `boot_params.screen_info` structure which is defined in [include/uapi/linux/screen_info.h](https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/screen_info.h) header file.
이제 비디오 모드 초기화로 직접 이동할 수 있습니다. `RESET_HEAP()`에서 `set_video`함수를 호출하고 멈췄습니다. 다음은 [include/uapi/linux/screen_info.h](https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/screen_info.h)헤더 파일에 정의된 `boot_params.screen_info`구조에 비디오 모드 파라미터를  저장하는 `store_mode_params`의 호출입니다.

If we look at the `store_mode_params` function, we can see that it starts with a call to the `store_cursor_position` function. As you can understand from the function name, it gets information about the cursor and stores it.
`store_mode_params`함수를 보면 `store_cursor_position`함수를 호출하며 시작하는 것을 볼 수 있습니다. 함수 이름에서 알 수 있듯이 커서에 대한 정보를 가져와서 저장합니다.

First of all, `store_cursor_position` initializes two variables which have type `biosregs` with `AH = 0x3`, and calls the `0x10` BIOS interruption. After the interruption is successfully executed, it returns row and column in the `DL` and `DH` registers. Row and column will be stored in the `orig_x` and `orig_y` fields of the `boot_params.screen_info` structure.
첫째로 `store_cursor_position`가 가진 `biosregs`와 함께 `AH = 0x3` 두 변수를 초기화하고 `0x10` BIOS 인터럽트를 호출합니다. 인터럽트가 성공적으로 실행되면 `DL`과 `DH`레지스터의행렬을 반환합니다. 행렬은 `boot_params.screen_info`구조의 `orig_x`, `orig_y`필드를 저장할 수 있습니다.

After `store_cursor_position` is executed, the `store_video_mode` function will be called. It just gets the current video mode and stores it in `boot_params.screen_info.orig_video_mode`.
`store_cursor_position`의 실행 후 `store_video_mode`함수가 호출됩니다. 이것은 현재 비디오 모드를 얻고 `boot_params.screen_info.orig_video_mode`를 저장합니다.

After this, `store_mode_params` checks the current video mode and sets the `video_segment`. After the BIOS transfers control to the boot sector, the following addresses are for video memory:
그런 다음, `store_mode_params`는 현재 비디오 모드를 체크하고 `video_segment`를 설정합니다. BIOS가 부트 섹터 컨트롤을 전송한 후 따라오는 주소는 비디오 메모리 용입니다:

```
0xB000:0x0000 	32 Kb 	Monochrome Text Video Memory
0xB800:0x0000 	32 Kb 	Color Text Video Memory
```

So we set the `video_segment` variable to `0xb000` if the current video mode is MDA, HGC, or VGA in monochrome mode and to `0xb800` if the current video mode is in color mode. After setting up the address of the video segment, the font size needs to be stored in `boot_params.screen_info.orig_video_points` with:
따라서 현재 비디오 모드의 MDA, HGC 또는 VGA가 모노크롬 모드이고 `0xb800`이거나 현재 비디오 모드가 컬러 모드이면 `video_segment`변수를 `0xb000`로 설정합니다. 비디오 세그먼트의 주소를 설정했으면 `boot_params.screen_info.orig_video_points`에 폰트 사이즈를 저장해야 합니다.

```C
set_fs(0);
font_size = rdfs16(0x485);
boot_params.screen_info.orig_video_points = font_size;
```

First of all, we put 0 in the `FS` register with the `set_fs` function. We already saw functions like `set_fs` in the previous part. They are all defined in [arch/x86/boot/boot.h](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/boot.h). Next, we read the value which is located at address `0x485` (this memory location is used to get the font size) and save the font size in `boot_params.screen_info.orig_video_points`.
첫번째로 `set_fs`함수를 이용해 `F5`레지스터에 0을 넣습니다. 이전 파트에서 `set_fs`같은 함수는 이미 봤습니다. 이것들은 모두 [arch/x86/boot/boot.h](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/boot.h)에 정의되어 있습니다. 다음으로 주소 `0x485`(이 메모리 위치는 폰트 사이즈를 가져오는데 사용)에서 값을 읽고 `boot_params.screen_info.orig_video_points`에 폰트 사이즈를 저장합니다.

```C
x = rdfs16(0x44a);
y = (adapter == ADAPTER_CGA) ? 25 : rdfs8(0x484)+1;
```

Next, we get the amount of columns by address `0x44a` and rows by address `0x484` and store them in `boot_params.screen_info.orig_video_cols` and `boot_params.screen_info.orig_video_lines`. After this, execution of `store_mode_params` is finished.
다음으로 주소`0x44a`에서 열의 양을, 주소`0x484`에서 행의 양을 가져오고 그것들을 `boot_params.screen_info.orig_video_cols`과 `boot_params.screen_info.orig_video_lines`에 저장합니다. 그 다음 `store_mode_params`을 실행하면 끝입니다.

Next we can see the `save_screen` function which just saves the contents of the screen to the heap. This function collects all the data which we got in the previous functions (like the rows and columns, and stuff) and stores it in the `saved_screen` structure, which is defined as:
다음으로 화면의 내용을 힙에 저장하는 `save_screen`함수입니다. 이 함수는 이전의 함수에서 얻은 모든 데이터(행과 열, 재료 등)를 수집하여 다음과 같이 정의된 `saved_screen`구조에 저장합니다.

```C
static struct saved_screen {
	int x, y;
	int curx, cury;
	u16 *data;
} saved;
```

It then checks whether the heap has free space for it with:
그런 다음 힙에 여유 공간이 있는지 확인합니다.

```C
if (!heap_free(saved.x*saved.y*sizeof(u16)+512))
		return;
```

and allocates space in the heap if it is enough and stores `saved_screen` in it.
공간이 충분하면 힙에 공간을 할당하고 `saved_screen`에 저장합니다.

The next call is `probe_cards(0)` from [arch/x86/boot/video-mode.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/video-mode.c) source code file. It goes over all video_cards and collects the number of modes provided by the cards. Here is the interesting part, we can see the loop:
다음 호출은 [arch/x86/boot/video-mode.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/video-mode.c)소스 코드 파일의 `probe_cards(0)`입니다. 이것은 모든 비디오 카드를 지나가며 카드가 제공하는 모드의 개수를 수집합니다. 다음은 흥미로운 부분으로 루프를 볼 수 있습니다. 

```C
for (card = video_cards; card < video_cards_end; card++) {
  /* collecting number of modes here */
}
```

but `video_cards` is not declared anywhere. The answer is simple: every video mode presented in the x86 kernel setup code has a definition that looks like this:
그러나 `video_cards`가 어디에도 선언되지 않았습니다. 답은 간단합니다. x86 커널 설정 코드에 표시되는 모든 비디오 모드는 다음과 같은 정의를 가집니다.

```C
static __videocard video_vga = {
	.card_name	= "VGA",
	.probe		= vga_probe,
	.set_mode	= vga_set_mode,
};
```

where `__videocard` is a macro:
`__videocard`매크로의 위치:

```C
#define __videocard struct card_info __attribute__((used,section(".videocards")))
```

which means that the `card_info` structure:
이는 `card_info`구조를 의미합니다.

```C
struct card_info {
	const char *card_name;
	int (*set_mode)(struct mode_info *mode);
	int (*probe)(void);
	struct mode_info *modes;
	int nmodes;
	int unsafe;
	u16 xmode_first;
	u16 xmode_n;
};
```

is in the `.videocards` segment. Let's look in the [arch/x86/boot/setup.ld](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/setup.ld) linker script, where we can find:
`.videocards`세그먼트에서 우리가 찾을 수 있는 링커 스크립트[arch/x86/boot/setup.ld](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/setup.ld)를 살펴봅시다.

```
	.videocards	: {
		video_cards = .;
		*(.videocards)
		video_cards_end = .;
	}
```

It means that `video_cards` is just a memory address and all `card_info` structures are placed in this segment. It means that all `card_info` structures are placed between `video_cards` and `video_cards_end`, so we can use a loop to go over all of it. After `probe_cards` executes we have a bunch of structures like `static __videocard video_vga` with the `nmodes` (the number of video modes) filled in.
이것은 `video_cards`는 단순한 메모리 주소이며 모든 `card_info`구조는 세그먼트에 배치된다는 것을 의미합니다. 모든 `card_info` 구조는 `video_cards`와 `video_cards_end` 사이에 배치되므로 루프를 사용하여 모든 구조를 살핍니다. `probe_cards`가 실행되면 `static __videocard video_vga`이나 `nmodes`(비디오 모드의 수)가 채워진 것과 같은 구조들을 가집니다.


After the `probe_cards` function is done, we move to the main loop in the `set_video` function. There is an infinite loop which tries to set up the video mode with the `set_mode` function or prints a menu if we passed `vid_mode=ask` to the kernel command line or if video mode is undefined.
다음으로 `probe_cards`함수를 수행하면 `set_video`함수의 메인루프로 이동합니다. 커널 커맨드 라인에 `vid_mode=ask`가 전달되거나 비디오 모드가 정의되지 않은 경우 `set_mode`함수로 비디오 모드를 설정하거나 메뉴를 출력하는 무한루프가 있습니다.

The `set_mode` function is defined in [video-mode.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/video-mode.c) and gets only one parameter, `mode`, which is the number of video modes (we got this value from the menu or in the start of `setup_video`, from the kernel setup header).
`set_mode`함수는 [video-mode.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/video-mode.c)에 정의되어 있으며 비디오 모드의 개수인 매개변수 하나, `mode`만 가져옵니다(이 값은 메뉴 또는 커널 설정 헤더의 시작부분 `setup_video`에서 얻음).


The `set_mode` function checks the `mode` and calls the `raw_set_mode` function. The `raw_set_mode` calls the selected card's `set_mode` function, i.e. `card->set_mode(struct mode_info*)`. We can get access to this function from the `card_info` structure. Every video mode defines this structure with values filled depending upon the video mode (for example for `vga` it is the `video_vga.set_mode` function. See the above example of the `card_info` structure for `vga`). `video_vga.set_mode` is `vga_set_mode`, which checks the vga mode and calls the respective function:
`set_mode`함수는 `mode`를 확인하고 `raw_set_mode`함수를 호출합니다. `raw_set_mode`는 `set_mode`함수에서 선택된 카드 `card->set_mode(struct mode_info*)`를 호출합니다. `card_info`구조 함수에 접근할 수 있습니다. 모든 비디오 모드는 비디오 모드에 의해 채워진 값으로 구조를 정의합니다.(예를 들어 `vga`는 `video_vga.set_mode`함수입니다. 위의 예시를 보면 `card_info`구조는 `vga`입니다). `video_vga.set_mode`는 `vga_set_mode`이므로 vga 모드를 확인하고 해당 함수를 호출합니다.

```C
static int vga_set_mode(struct mode_info *mode)
{
	vga_set_basic_mode();

	force_x = mode->x;
	force_y = mode->y;

	switch (mode->mode) {
	case VIDEO_80x25:
		break;
	case VIDEO_8POINT:
		vga_set_8font();
		break;
	case VIDEO_80x43:
		vga_set_80x43();
		break;
	case VIDEO_80x28:
		vga_set_14font();
		break;
	case VIDEO_80x30:
		vga_set_80x30();
		break;
	case VIDEO_80x34:
		vga_set_80x34();
		break;
	case VIDEO_80x60:
		vga_set_80x60();
		break;
	}
	return 0;
}
```

Every function which sets up video mode just calls the `0x10` BIOS interrupt with a certain value in the `AH` register.
비디오 모드를 설정하는 모든 함수는 `AH`레지스터의 특정 값으로 `0x10` BIOS 인터럽트를 호출합니다.

After we have set the video mode, we pass it to `boot_params.hdr.vid_mode`.
비디오 모드를 설정한 다음 `boot_params.hdr.vid_mode`를 전달합니다.

Next, `vesa_store_edid` is called. This function simply stores the [EDID](https://en.wikipedia.org/wiki/Extended_Display_Identification_Data) (**E**xtended **D**isplay **I**dentification **D**ata) information for kernel use. After this `store_mode_params` is called again. Lastly, if `do_restore` is set, the screen is restored to an earlier state.
다음 `vesa_store_edid`이 호출됩니다. 이 함수는 커널의 사용 정보 [EDID](https://en.wikipedia.org/wiki/Extended_Display_Identification_Data) (**E**xtended **D**isplay **I**dentification **D**ata)를 간단하게 저장합니다. 다음으로 `store_mode_params`을 다시 호출합니다. 마지막으로 `do_restore`을 설정하면 화면이 이전 상태로 복원됩니다.

Having done this, the video mode setup is complete and now we can switch to the protected mode.
이 작업을 완료하면 비디오 모드 설정이 완료되었으며 이제 보호 모드로 전환할 수 있습니다.

Last preparation before transition into protected mode
보호 모드로 전환하기 전 마지막 준비
--------------------------------------------------------------------------------

We can see the last function call - `go_to_protected_mode` - in [arch/x86/boot/main.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c). As the comment says: `Do the last things and invoke protected mode`, so let's see what these last things are and switch into protected mode.
[arch/x86/boot/main.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/main.c)의 `go_to_protected_mode`에서 마지막 함수 호출을 볼 수 있습니다. 주석:`Do the last things and invoke protected mode`에서 알 수 있듯이 마지막 사항을 확인하고 보호모드로 전환하십시오.


The `go_to_protected_mode` function is defined in [arch/x86/boot/pm.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/pm.c). It contains some functions which make the last preparations before we can jump into protected mode, so let's look at it and try to understand what it does and how it works.
`go_to_protected_mode`함수는 [arch/x86/boot/pm.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/pm.c)에 정의되어 있습니다. 여기에는 보호 모드로 들어가기 전에 마지막으로 준비해야 하는 함수가 포함되어 있으니 함수를 살펴보고 작동 방식을 이해하려고 노력하십시오.

First is the call to the `realmode_switch_hook` function in `go_to_protected_mode`. This function invokes the real mode switch hook if it is present and disables [NMI](http://en.wikipedia.org/wiki/Non-maskable_interrupt). Hooks are used if the bootloader runs in a hostile environment. You can read more about hooks in the [boot protocol](https://www.kernel.org/doc/Documentation/x86/boot.txt) (see **ADVANCED BOOT LOADER HOOKS**).
먼저 `go_to_protected_mode`의 `realmode_switch_hook`함수를 호출합니다. 이 함수는 리얼 모드 스위치 후크가 있으면 이를 호출하고 [NMI](http://en.wikipedia.org/wiki/Non-maskable_interrupt)를 비활성화합니다. 부트로더가 적대적인 환경에서 실행되는 경우 후크가 사용됩니다. [boot protocol](https://www.kernel.org/doc/Documentation/x86/boot.txt)에서 후크에 대한 자세한 내용을 볼 수 있습니다(**고급 부트 로더 후크**참조).


The `realmode_switch` hook presents a pointer to the 16-bit real mode far subroutine which disables non-maskable interrupts. After the `realmode_switch` hook (it isn't present for me) is checked, Non-Maskable Interrupts(NMI) is disabled:
`realmode_switch`는 16비트 리얼 모드까지 마스크 불가능 인터럽트를 비활성화, 서브루틴에 대한 포인터를 제공합니다. `realmode_switch`후크를 확인한 후, 마스크 불가능 인터럽트(NMI)는 사용할 수 없습니다.

```assembly
asm volatile("cli");
outb(0x80, 0x70);	/* Disable NMI */
io_delay();
```

At first, there is an inline assembly statement with a `cli` instruction which clears the interrupt flag (`IF`). After this, external interrupts are disabled. The next line disables NMI (non-maskable interrupt).
처음에 인터럽트 플래그 (`IF`)를 지우는 인라인 어셈블리 명령문 `cli`가 있습니다. 다음으로 외부 인터럽트가 비활성화됩니다. 다음 줄은 NMI(마스크 불가능 인터럽트)를 비활성화합니다.

An interrupt is a signal to the CPU which is emitted by hardware or software. After getting such a signal, the CPU suspends the current instruction sequence, saves its state and transfers control to the interrupt handler. After the interrupt handler has finished it's work, it transfers control back to the interrupted instruction. Non-maskable interrupts (NMI) are interrupts which are always processed, independently of permission. They cannot be ignored and are typically used to signal for non-recoverable hardware errors. We will not dive into the details of interrupts now but we will be discussing them in the coming posts.
인터럽트는 하드웨어나 소프트웨어에 의해 발생하는 CPU신호 입니다. 신호를 얻은 후 CPU는 현재 명령 시퀀스를 중단하고 상태를 저장하며, 컨트롤을 인터럽트 핸들러로 전송합니다. 다음으로 인터럽트 핸들러는 작업을 완료하고 컨트롤을 다시 인터럽트 명령으로 전송합니다. 마스크 불가능 인터럽트(NMI)는 권한에 관계없이 항상 실행되는 인터럽트입니다. 이것들은 무시할 수 없고 일반적으로 복구할 수 없는 하드웨어 오류를 나타내는데 사용됩니다. 지금은 인터럽트의 세부사항에 들어가지 않고 다음 포스트에서 논의할 것입니다.

Let's get back to the code. We can see in the second line that we are writing the byte `0x80` (disabled bit) to `0x70` (the CMOS Address register). After that, a call to the `io_delay` function occurs. `io_delay` causes a small delay and looks like:
다시 코드로 옵니다. 두번째 줄에서 바이트`0x80`(비활성화된 바이트)를 `0x70`(CMOS 주소 레지스터)에 쓰는 것을 볼 수 있습니다. 그 후 `io_delay`함수 호출이 발생합니다. `io_delay`에서 다음과 같이 약간의 딜레이가 있습니다:

```C
static inline void io_delay(void)
{
	const u16 DELAY_PORT = 0x80;
	asm volatile("outb %%al,%0" : : "dN" (DELAY_PORT));
}
```

To output any byte to the port `0x80` should delay exactly 1 microsecond. So we can write any value (the value from `AL` in our case) to the `0x80` port. After this delay the `realmode_switch_hook` function has finished execution and we can move to the next function.
`0x80`포트에 바이트를 출력하면 정확히 1마이크로 초가 지연되어야 합니다. 따라서 어떤 값(이 경우 AL)이라도 `0x80`포트에 쓸 수 있습니다. 이 딜레이 후에 `realmode_switch_hook`함수의 실행이 끝나고 다음 함수로 넘어갈 수 있습니다.

The next function is `enable_a20`, which enables the [A20 line](http://en.wikipedia.org/wiki/A20_line). This function is defined in [arch/x86/boot/a20.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/a20.c) and it tries to enable the A20 gate with different methods. The first is the `a20_test_short` function which checks if A20 is already enabled or not with the `a20_test` function:
다음 함수는 `enable_a20`으로 [A20 line](http://en.wikipedia.org/wiki/A20_line)에서 활성화 할 수 있습니다. 이 함수는 [arch/x86/boot/a20.c](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/a20.c)에 정의되었으며 다른 방법으로 A20 게이트를 활성화하려 합니다. 첫번째로 `a20_test_short`함수는 `a20_test`함수와 함께 A20의 활성화 여부를 확인합니다:

```C
static int a20_test(int loops)
{
	int ok = 0;
	int saved, ctr;

	set_fs(0x0000);
	set_gs(0xffff);

	saved = ctr = rdfs32(A20_TEST_ADDR);

        while (loops--) {
		wrfs32(++ctr, A20_TEST_ADDR);
		io_delay();	/* Serialize and make delay constant */
		ok = rdgs32(A20_TEST_ADDR+0x10) ^ ctr;
		if (ok)
			break;
	}

	wrfs32(saved, A20_TEST_ADDR);
	return ok;
}
```

First of all, we put `0x0000` in the `FS` register and `0xffff` in the `GS` register. Next, we read the value at the address `A20_TEST_ADDR` (it is `0x200`) and put this value into the variables `saved` and `ctr`.
우선 `FS`레지스터에 `0x0000`을 넣고 `GS`레지스터에 `0xffff`를 넣습니다. 다음으로 주소`A20_TEST_ADDR`(`0x200`)에서 값을 읽고 이 값을 변수`saved`와 `ctr`에 넣습니다.

Next, we write an updated `ctr` value into `fs:A20_TEST_ADDR` or `fs:0x200` with the `wrfs32` function, then delay for 1ms, and then read the value from the `GS` register into the address `A20_TEST_ADDR+0x10`. In a case when `a20` line is disabled, the address will be overlapped, in other case if it's not zero `a20` line is already enabled the A20 line.
다음, `wrfs32`함수로 업데이트된 `ctr`값을 `fs:A20_TEST_ADDR` 또는 `fs:0x200`에 넣습니다. 1마이크로초 뒤 주소 `A20_TEST_ADDR+0x10`에서 `GS`레지스터의 값을 읽습니다. `a20` 라인이 비활성화된 경우 주소가 겹치며,  `a20`라인이 0이 아닌 경우 이미 A20라인이 활성화 된 것입니다.

If A20 is disabled, we try to enable it with a different method which you can find in `a20.c`. For example, it can be done with a call to the `0x15` BIOS interrupt with `AH=0x2041`.
A20이 비활성화된 경우 `a20.c`에서 다른 방법을 찾아 활성화해야 합니다. 예를 들어, `AH=0x2041`를 써서 `0x15`BIOS 인터럽트를 호출할 수 있습니다.

If the `enable_a20` function finished with a failure, print an error message and call the function `die`. You can remember it from the first source code file where we started - [arch/x86/boot/header.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/header.S):
`enable_a20`함수가 실패하면 에러 메시지를 출력하고 `die`함수를 호출합니다. 첫 소스 코드 파일[arch/x86/boot/header.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/header.S)에서 이를 기억할 수 있습니다.

```assembly
die:
	hlt
	jmp	die
	.size	die, .-die
```

After the A20 gate is successfully enabled, the `reset_coprocessor` function is called:
A20 게이트가 성공적으로 활성화되면 `reset_coprocessor`함수가 호출됩니다.

```C
outb(0, 0xf0);
outb(0, 0xf1);
```

This function clears the Math Coprocessor by writing `0` to `0xf0` and then resets it by writing `0` to `0xf1`.
이 함수는 `0xf0`에 `0`을 적어서 수학 보조프로세서를 지우고 `0xf1`에 `0`을 적어서 초기화합니다.

After this, the `mask_all_interrupts` function is called:
그 다음 `mask_all_interrupts`함수가 호출됩니다:

```C
outb(0xff, 0xa1);       /* Mask all interrupts on the secondary PIC */
outb(0xfb, 0x21);       /* Mask all but cascade on the primary PIC */
```

This masks all interrupts on the secondary PIC (Programmable Interrupt Controller) and primary PIC except for IRQ2 on the primary PIC.
이 마스크는 1차 PIC의 IRQ2를 제외한 2차 PIC(Programmable Interrupt Controller)와 1차 PIC의  모든 인터럽트를 마스크합니다.

And after all of these preparations, we can see the actual transition into protected mode.
모든 준비 후에 실제 보호 모드로 전환되는 것을 볼 수 있습니다.

Set up the Interrupt Descriptor Table
인터럽트 설명자 테이블 설정
--------------------------------------------------------------------------------

Now we set up the Interrupt Descriptor table (IDT) in the `setup_idt` function:
이제 `setup_idt`함수로 인터럽트 디스크립터 테이블(IDT)을 설정합니다.

```C
static void setup_idt(void)
{
	static const struct gdt_ptr null_idt = {0, 0};
	asm volatile("lidtl %0" : : "m" (null_idt));
}
```

which sets up the Interrupt Descriptor Table (describes interrupt handlers and etc.). For now, the IDT is not installed (we will see it later), but now we just load the IDT with the `lidtl` instruction. `null_idt` contains the address and size of the IDT, but for now they are just zero. `null_idt` is a `gdt_ptr` structure, it is defined as:
인터럽트 디스크립터 테이블을 설정합니다(인터럽트 핸들러 등을 설명). 현재는 IDT가 설치되지 않았지만(나중에 볼 예정), `lidtl` 명령과 IDT를 불러오면 됩니다. `null_idt`는 주소와 IDT의 크기를 포함하지만 현재는 0입니다. `null_idt`는 `gdt_ptr`구조로 다음과 같이 정의됩니다:

```C
struct gdt_ptr {
	u16 len;
	u32 ptr;
} __attribute__((packed));
```

where we can see the 16-bit length(`len`) of the IDT and the 32-bit pointer to it (More details about the IDT and interruptions will be seen in the next posts). ` __attribute__((packed))` means that the size of `gdt_ptr` is the minimum required size. So the size of the `gdt_ptr` will be 6 bytes here or 48 bits. (Next we will load the pointer to the `gdt_ptr` to the `GDTR` register and you might remember from the previous post that it is 48-bits in size).
여기서 16비트 길이(`len`)의 IDT와 이에 대한 32비트 포인터를 볼 수 있습니다(IDT와 인터럽션에 대해 자세한 내용은 다음 포스트에서 볼 수 있습니다). ` __attribute__((packed))`는 `gdt_ptr`가 요구하는 최소한의 크기를 의미합니다. 따라서 `gdt_ptr`의 크기는 여기서도 6바이트 또는 48비트입니다. (다음에 `GDTR`레지스터에서 `gdt_ptr`포인터를 부르고 이전 포스트에서 이것이 48비트라고 한 것을 기억할 수도 있습니다).

Set up Global Descriptor Table
글로벌 디스크립터 테이블 설정
--------------------------------------------------------------------------------

Next is the setup of the Global Descriptor Table (GDT). We can see the `setup_gdt` function which sets up the GDT (you can read about it in the post [Kernel booting process. Part 2.](linux-bootstrap-2.md#protected-mode)). There is a definition of the `boot_gdt` array in this function, which contains the definition of the three segments:
다음은 글로벌 디스크립터 테이블(GDT)의 설정입니다. GDT를 설정한 `setup_gdt`함수를 볼 수 있습니다(포스트 [커널 부팅 과정. 파트 2.](linux-bootstrap-2.md#protected-mode)에서 읽을 수 있습니다). `boot_gdt`배열 함수의 정의는 세그먼트 3개의 정의를 포함합니다:

```C
static const u64 boot_gdt[] __attribute__((aligned(16))) = {
	[GDT_ENTRY_BOOT_CS] = GDT_ENTRY(0xc09b, 0, 0xfffff),
	[GDT_ENTRY_BOOT_DS] = GDT_ENTRY(0xc093, 0, 0xfffff),
	[GDT_ENTRY_BOOT_TSS] = GDT_ENTRY(0x0089, 4096, 103),
};
```

for code, data and TSS (Task State Segment). We will not use the task state segment for now, it was added there to make Intel VT happy as we can see in the comment line (if you're interested you can find the commit which describes it - [here](https://github.com/torvalds/linux/commit/88089519f302f1296b4739be45699f06f728ec31)). Let's look at `boot_gdt`. First of all note that it has the `__attribute__((aligned(16)))` attribute. It means that this structure will be aligned by 16 bytes.
코드, 데이터 및 TSS(Task State Segment)에서 현재 작업 상태 세그먼트를 사용하지 않을 것입니다. 주석 행에서 볼 수 있듯이 이것은 Intel VT를 적절히하기 위해 추가되었습니다(관심이 있는 경우 [여기](https://github.com/torvalds/linux/commit/88089519f302f1296b4739be45699f06f728ec31)에서 설명하는 커밋을 찾을 수 있습니다). `boot_gdt`을 봅시다. 우선 `__attribute__((aligned(16)))`속성이 있습니다. 이는 이 구조가 16바이트로 정렬되는 것을 의미합니다.

Let's look at a simple example:
간단한 예제를 봅시다:

```C
#include <stdio.h>

struct aligned {
	int a;
}__attribute__((aligned(16)));

struct nonaligned {
	int b;
};

int main(void)
{
	struct aligned    a;
	struct nonaligned na;

	printf("Not aligned - %zu \n", sizeof(na));
	printf("Aligned - %zu \n", sizeof(a));

	return 0;
}
```

Technically a structure which contains one `int` field must be 4 bytes in size, but an `aligned` structure will need 16 bytes to store in memory:
기술적으로 `int`필드를 포함하는 구조는 4바이트여야 하지만 `aligned`구조는 메모리에 저장하기 위해 16바이트가 필요합니다.

```
$ gcc test.c -o test && test
Not aligned - 4
Aligned - 16
```

The `GDT_ENTRY_BOOT_CS` has index - 2 here, `GDT_ENTRY_BOOT_DS` is `GDT_ENTRY_BOOT_CS + 1` and etc. It starts from 2, because the first is a mandatory null descriptor (index - 0) and the second is not used (index - 1).
`GDT_ENTRY_BOOT_CS`는 인덱스 2개, `GDT_ENTRY_BOOT_DS`는 `GDT_ENTRY_BOOT_CS + 1` 등이 있습니다. 첫번째는 필수 널 디스크립터(index - 0)여서 2에서 시작하고 두번째는 사용하지 않습니다(index -1).

`GDT_ENTRY` is a macro which takes flags, base, limit and builds a GDT entry. For example, let's look at the code segment entry. `GDT_ENTRY` takes the following values:
`GDT_ENTRY`는 flags, base, limit 및 GDT 항목을 작성하는 매크로입니다. 예를 들어, 코드 세크먼트 항목을 살펴봅시다. `GDT_ENTRY`는 다음 값을 갖습니다:

* base  - 0
* limit - 0xfffff
* flags - 0xc09b

What does this mean? The segment's base address is 0, and the limit (size of segment) is - `0xfffff` (1 MB). Let's look at the flags. It is `0xc09b` and it will be:
이것은 무엇을 의미하는가? 세크먼트의 기본 주소는 0이고, limit(세그먼트의 크기)는 `0xfffff`(1MB)입니다. flags를 봅시다. flags는 `0xc09b`이고 다음과 같습니다:

```
1100 0000 1001 1011
```

in binary. Let's try to understand what every bit means. We will go through all bits from left to right:
이진법으로 모든 비트의 의미를 이해해봅시다. 모든 비트를 왼쪽에서 오른쪽으로 살펴봅시다.

* 1    - (G) granularity bit
* 1    - (G) 
* 1    - (D) if 0 16-bit segment; 1 = 32-bit segment
* 1    - (D) 16비트 세그먼트인 경우; 1 = 32비트 세그먼트
* 0    - (L) executed in 64-bit mode if 1
* 0    - (L) 1인 경우 64비트 모드에서 실행
* 0    - (AVL) available for use by system software
* 0    - (AVL) 시스템 소프트웨어에서 사용할 수 있는
* 0000 - 4-bit length 19:16 bits in the descriptor
* 0000 - 디스크립터에서 4비트의 길이는 19:16비트
* 1    - (P) segment presence in memory
* 1    - (P) 메모리에서 세그먼트의 존재
* 00   - (DPL) - privilege level, 0 is the highest privilege
* 00   - (DPL) - 권한 레벨, 0이 가장 높은 권한
* 1    - (S) code or data segment, not a system segment
* 1    - (S) 시스템 세그먼트가 아닌 코드나 데이터 세그먼트
* 101  - segment type execute/read/
* 101  - 세그먼트 타입 실행/읽기/
* 1    - accessed bit
* 1    - 액세스 된 비트

You can read more about every bit in the previous [post](linux-bootstrap-2.md) or in the [Intel® 64 and IA-32 Architectures Software Developer's Manuals 3A](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html).
이전 [포스트](linux-bootstrap-2.md) 또는 [인텔® 64 and IA-32 아키텍쳐 소프트웨어 개발자 메뉴얼 3A](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html)에서 모든 비트에 대한 자세한 내용을 읽을 수 있습니다.

After this we get the length of the GDT with:
다음과 같이 GDT의 길이를 얻습니다:

```C
gdt.len = sizeof(boot_gdt)-1;
```

We get the size of `boot_gdt` and subtract 1 (the last valid address in the GDT).
`boot_gdt`의 크기를 얻고 1을 뺍니다(GDT의 마지막 유효주소).

Next we get a pointer to the GDT with:
다음으로 GDT의 포인터를 얻습니다:

```C
gdt.ptr = (u32)&boot_gdt + (ds() << 4);
```

Here we just get the address of `boot_gdt` and add it to the address of the data segment left-shifted by 4 bits (remember we're in real mode now).
`boot_gdt`의 주소를 얻고 왼쪽으로 4비트 이동한 데이터 세그먼트의 주소를 추가합니다(현재 리얼모드인 것을 기억하십시오).

Lastly we execute the `lgdtl` instruction to load the GDT into the GDTR register:
마지막으로 GDT를 GDTR레지스터에 로드하는 `lgdtl`명령을 실행합니다.

```C
asm volatile("lgdtl %0" : : "m" (gdt));
```

Actual transition into protected mode
보호 모드로의 실제 전환
--------------------------------------------------------------------------------

This is the end of the `go_to_protected_mode` function. We loaded the IDT and GDT, disabled interrupts and now can switch the CPU into protected mode. The last step is calling the `protected_mode_jump` function with two parameters:
이것이 `go_to_protected_mode`함수의 끝입니다. IDT 및 GDT를 로드하고 인터럽트를 비활성화했으며 이제 CPU를 보호모드로 전환할 수 있습니다. 마지막 단계는 `protected_mode_jump`함수와 두 매개변수를 호출하는 것입니다.

```C
protected_mode_jump(boot_params.hdr.code32_start, (u32)&boot_params + (ds() << 4));
```

which is defined in [arch/x86/boot/pmjump.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/pmjump.S).
[arch/x86/boot/pmjump.S](https://github.com/torvalds/linux/blob/v4.16/arch/x86/boot/pmjump.S)에 정의되어 있습니다.

It takes two parameters:
두 매개변수가 하는 일은:

* address of the protected mode entry point
* 보호 모드 진입 포인트의 주소
* address of `boot_params`
* `boot_params`의 주소

Let's look inside `protected_mode_jump`. As I wrote above, you can find it in `arch/x86/boot/pmjump.S`. The first parameter will be in the `eax` register and the second one is in `edx`.
`protected_mode_jump`의 내부를 봅시다. 위에 쓴 것처럼 `arch/x86/boot/pmjump.S`를 찾을 수 있습니다. 첫번째 매개변수는 `eax`레지스터에 있고 두번째는 `edx`에 있습니다.

First of all, we put the address of `boot_params` in the `esi` register and the address of the code segment register `cs` in `bx`. After this, we shift `bx` by 4 bits and add it to the memory location labeled `2` (which is `(cs << 4) + in_pm32`, the physical address to jump after transitioned to 32-bit mode) and jump to label `1`. So after this `in_pm32` in label `2` will be overwritten with `(cs << 4) + in_pm32`.
먼저, `boot_params`의 주소에 `esi`레지스터를 넣고 코드 세그먼트 레지스터`cs`에 `bx`를 넣습니다. 그런 다음 `bx`를 4비트 씩 이동해 레이블`2`로 지정된 메모리위치(즉, `(cs << 4) + in_pm32`를 32비트 모드로 전환하고 옮길 물리 주소)에 추가하고 레이블`1`로 이동합니다. 따라서 레이블`2`의 `in_pm32`은 `(cs << 4) + in_pm32`로 덮어 쓰여집니다.

Next we put the data segment and the task state segment in the `cx` and `di` registers with:
다음으로 데이터 세그먼트와 작업 상태 세그먼트를 `cx`와 `di`레지스터에 넣습니다.

```assembly
movw	$__BOOT_DS, %cx
movw	$__BOOT_TSS, %di
```

As you can read above `GDT_ENTRY_BOOT_CS` has index 2 and every GDT entry is 8 byte, so `CS` will be `2 * 8 = 16`, `__BOOT_DS` is 24 etc.
위에서 읽었 듯이 `GDT_ENTRY_BOOT_CS`는 인덱스 2개를 가졌으며 모든 GDT항목이 8바이트입니다. 따라서 `CS`는 `2 * 8 = 16`이 되고 `__BOOT_DS`는 24입니다.

Next, we set the `PE` (Protection Enable) bit in the `CR0` control register:
다음으로 `CR0`제어 레지스터에서 `PE`(보호 활성화) 비트를 설정합니다.

```assembly
movl	%cr0, %edx
orb	$X86_CR0_PE, %dl
movl	%edx, %cr0
```

and make a long jump to protected mode:
보호 모드로 이동합니다.

```assembly
	.byte	0x66, 0xea
2:	.long	in_pm32
	.word	__BOOT_CS
```

where:

* `0x66` is the operand-size prefix which allows us to mix 16-bit and 32-bit code
* `0x66`은 16비트와 32비트를 혼합할 수 있는 피연산자 크기 접두사입니다. 
* `0xea` - is the jump opcode
* `in_pm32` is the segment offset under protect mode, which has value `(cs << 4) + in_pm32` derived from real mode
* `in_pm32`은 보호모드에서 세그먼트 오프셋이며 실제 모드에서 파생된 값`(cs << 4) + in_pm32`이 있습니다.
* `__BOOT_CS` is the code segment we want to jump to.
* `__BOOT_CS`는 이동하려는 코드 세그먼트 입니다.

After this we are finally in protected mode:
다음은 드디어 보호 모드입니다.

```assembly
.code32
.section ".text32","ax"
```

Let's look at the first steps taken in protected mode. First of all we set up the data segment with:
보호 모드에서 수행된 첫 번째 단계를 살펴봅시다. 먼저 다음과 같이 데이터 세그먼트를 설정합니다.

```assembly
movl	%ecx, %ds
movl	%ecx, %es
movl	%ecx, %fs
movl	%ecx, %gs
movl	%ecx, %ss
```

If you paid attention, you can remember that we saved `$__BOOT_DS` in the `cx` register. Now we fill it with all segment registers besides `cs` (`cs` is already `__BOOT_CS`).
관심이 있다면 `cx`레지스터의 `$__BOOT_DS`에 저장한 것을 기억할 것입니다. 이제 `cs`(`cs`는 이미 `__BOOT_CS`)이외의 모든 세그먼트 레지스터를 채웁니다.

And setup a valid stack for debugging purposes:
그리고 디버깅 목적으로 유효한 스택을 설정합니다:

```assembly
addl	%ebx, %esp
```

The last step before the jump into 32-bit entry point is to clear the general purpose registers:
32비트 진입 포인트로 이동하기 전 마지막 단계는 범용 레지스터를 지우는 것입니다.

```assembly
xorl	%ecx, %ecx
xorl	%edx, %edx
xorl	%ebx, %ebx
xorl	%ebp, %ebp
xorl	%edi, %edi
```

And jump to the 32-bit entry point in the end:
그리고 마지막으로 32비트 진입 포인트로 이동합니다.

```
jmpl	*%eax
```

Remember that `eax` contains the address of the 32-bit entry (we passed it as the first parameter into `protected_mode_jump`).
`eax`는 32비트 진입 주소를 포함하는 것을 기억하십시오(`protected_mode_jump`의 첫번째 매개변수로 전달).

That's all. We're in protected mode and stop at its entry point. We will see what happens next in the next part.
끝났습니다. 보호 모드에 들어왔고 진입 포인트는 멈춥니다. 다음에 일어날 일은 다음 파트에서 보겠습니다.

Conclusion
결론
--------------------------------------------------------------------------------

This is the end of the third part about linux kernel insides. In the next part, we will look at the first steps we take in protected mode and transition into [long mode](http://en.wikipedia.org/wiki/Long_mode).
리눅스 커널 내부에 대한 세번째 파트의 끝입니다. 다음 파트에서는 보호 모드에서 시작하여 [long mode](http://en.wikipedia.org/wiki/Long_mode)로 전환하는 첫 번째 단계를 살펴보겠습니다.

If you have any questions or suggestions write me a comment or ping me at [twitter](https://twitter.com/0xAX).
질문이나 제안 사항이 있다면 코멘트를 남기거나 [트위터](https://twitter.com/0xAX)로 보내주세요.

**Please note that English is not my first language, And I am really sorry for any inconvenience. If you find any mistakes, please send me a PR with corrections at [linux-insides](https://github.com/0xAX/linux-internals).**
**영어는 모국어가 아니며 모든 불편한 점은 정말 죄송합니다. 실수를 발견하면 [linux-insides](https://github.com/0xAX/linux-internals)에서 수정 사항이 포함된 PR을 보내주십시오.**

링크
--------------------------------------------------------------------------------

* [VGA](http://en.wikipedia.org/wiki/Video_Graphics_Array)
* [VESA BIOS 확장](http://en.wikipedia.org/wiki/VESA_BIOS_Extensions)
* [자료 구조 정렬](http://en.wikipedia.org/wiki/Data_structure_alignment)
* [마스크 불가능 인터럽트](http://en.wikipedia.org/wiki/Non-maskable_interrupt)
* [A20](http://en.wikipedia.org/wiki/A20_line)
* [GCC 지정 초기화](https://gcc.gnu.org/onlinedocs/gcc-4.1.2/gcc/Designated-Inits.html)
* [GCC 타입 속성](https://gcc.gnu.org/onlinedocs/gcc/Type-Attributes.html)
* [이전 파트](linux-bootstrap-2.md)
