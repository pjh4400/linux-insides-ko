리눅스 커널에서의 타이머 및 시간 관리.Part 2.
================================================================================

 `clocksource` 프레임워크 소개
--------------------------------------------------------------------------------

이전 [파트](https://0xax.gitbooks.io/linux-insides/content/Timers/linux-timers-1.html)는 리눅스 커널에서 타이머와 시간 관리에 관련된 것을 설명하는 현재 챕터의 첫 번째 파트였습니다. 우리는 이전 파트에서 두 가지 개념을 알게되었습니다:

  * `jiffies`
  * `clocksource`

첫 번째는 [include/linux/jiffies.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/jiffies.h)헤더 파일에서 정의된 전역 변수이며 각 타이머 인터럽트 중 증가되는 카운터를 나타냅니다. 따라서 이 전역 변수에 접근할 수 있고 타이머 인터럽트 속도를 안다면 `jiffies`를 휴면 타임 유닛으로 변환할 수 있습니다. 우리가 이미 알고 있듯이 타이머 인터럽트 속도는 리눅스 커널에서 `HZ`라 불리는 컴파일-타임 상수로 표현됩니다. `HZ`의 값은 `CONFIG_HZ`커널 구성 옵션의 값과 같고 [arch/x86/configs/x86_64_defconfig](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/configs/x86_64_defconfig)커널 구성 파일을 보면, 다음을 볼 수 있습니다:

```
CONFIG_HZ_1000=y
```

커널 구성 옵션을 설정했습니다. 이것은 `CONFIG_HZ`의 값이 [x86_64](https://en.wikipedia.org/wiki/X86-64)아키텍쳐에 대한 디폴트 `1000`임을 의미합니다. 그래서, `jiffies`의 값을 `HZ`의 값으로 나누면:

```
jiffies / HZ
```

우리는 리눅스 커널이 작동을 시작한 순간부터 경과한 시간을 얻거나 다른 말로 시스템 [업타임](https://en.wikipedia.org/wiki/Uptime)을 얻습니다. `HZ`는 타이머 인터럽트의 양을 초 단위로 나타내므로 앞으로 일정 시간 동안 값을 설정할 수 있습니다. 예시:

```C
/* one minute from now */
unsigned long later = jiffies + 60*HZ;

/* five minutes from now */
unsigned long later = jiffies + 5*60*HZ;
```

이것은 리눅스 커널에서 매우 일반적인 일입니다. 예를 들어, [arch/x86/kernel/smpboot.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/smpboot.c)소스 코드 파일을 살펴보면, `do_boot_cpu`함수를 찾을 수 있습니다. 이 함수는 bootstrap프로세서 외에도 모든 프로세서를 부팅합니다. 응용프로그램 프로세서에서 응답을 10초 기다리는 snippet를 찾을 수 있습니다:

```C
if (!boot_error) {
	timeout = jiffies + 10*HZ;
	while (time_before(jiffies, timeout)) {
		...
		...
		...
		udelay(100);
	}
	...
	...
	...
}
```

여기서 `jiffies + 10*HZ`값을 `timeout`변수에 할당합니다. 이미 이해했듯이, 이것은 10초의 시간 초과를 의미합니다. 그런 다음 `time_before`매크로를 사용하여 현재 `jiffies`값과 시간초과를 비교하는 루프를 시작합니다.

또는 예를 들어 [Ensoniq Soundscape Elite](https://en.wikipedia.org/wiki/Ensoniq_Soundscape_Elite)사운드 카드에 대한 드라이버를 나타내는 [sound/isa/sscape.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/sound/isa/sscape)소스 코드 파일을 살펴보면, 그것의 시작 승인 시퀀스를 반환하는 On-Board 프로세에대해 주어진 시간초과를 기다리는 `obp_startup_ack`함수를 볼 수 있습니다:

```C
static int obp_startup_ack(struct soundscape *s, unsigned timeout)
{
	unsigned long end_time = jiffies + msecs_to_jiffies(timeout);

	do {
		...
		...
		...
		x = host_read_unsafe(s->io_base);
		...
		...
		...
		if (x == 0xfe || x == 0xff)
			return 1;
		msleep(10);
	} while (time_before(jiffies, end_time));

	return 0;
}
```

보시다시피, `jiffies`변수는 리눅스 커널 [코드](http://lxr.free-electrons.com/ident?i=jiffies)에서 매우 널리 사용됩니다. 이미 쓴 것처럼, 우리는 이전 파트의 `clocksource`와는 다른 새로운 시간 관리와 관련된 개념을 만났습니다. 우리는 이 개념의 간단한 설명과 클럭 소스 등록을 위한 API를 봤습니다. 이 파트에서 자세히 살펴봅시다.

 `clocksource`소개
--------------------------------------------------------------------------------

`clocksource`개념은 리눅스 커널에서 클럭 소스 관리를 위한 일반 API를 나타냅니다. 이를 위해 별도의 프레임워크가 왜 필요할까요? 처음으로 돌아가봅시다. `time`개념은 리눅스 커널 및 기타 운영 시스템 커널의 기본 개념입니다. 그리고 timekeeping은 이 개념을 사용하기 위한 필수요소 중 하나입니다. 예를 들어 리눅스 커널은 시스템 시작 이후의 경과 시간을 알고 업데이트해야하며, 현재 프로세스가 모든 프로세서에 대해 얼마나 오래 실행되었는지 결정해야합니다. 리눅스 커널은 어디서 시간에 대한 정보를 얻을까요? 우선 비휘발성 장치로 나타내는 실시간 클럭 또는 [RTC](https://en.wikipedia.org/wiki/Real-time_clock)입니다. [drivers/rtc](https://github.com/torvalds/linux/tree/master/drivers/rtc)디텍터리의 리눅스 커널에서 아키텍처 독립적 실시간 클럭 드라이버의 설정을 찾을 수 있습니다. 이외에도, 각 아키텍처는 아키텍처 의존적 실시간 클럭을 제공할 수 있습니다. 예를 들어 [x86](https://en.wikipedia.org/wiki/X86)아키텍처를 위한 `CMOS/RTC` - [arch/x86/kernel/rtc.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/rtc.c)가 있습니다. 두 번째는 주기적인 속도로 [인터럽트](https://en.wikipedia.org/wiki/Interrupt)를 자극하는 시스템 타이머입니다. 예를 들어 [IBM PC](https://en.wikipedia.org/wiki/IBM_Personal_Computer)호환 제품의 경우 [programmable interval timer](https://en.wikipedia.org/wiki/Programmable_interval_timer)가 있습니다.

우리는 이미 timekeeping을 위해 리눅스 커널에서 `jiffies`를 사용할 수 있다는 것을 압니다. `jiffies`는 `HZ`주파수로 업데이트된 전역 변수 읽기로 간주될 수 있습니다. 우리는 `HZ`가 `100`에서 `1000`의 [Hz](https://en.wikipedia.org/wiki/Hertz) 범위에 적절한 컴파일시간 커널 매개변수인 것을 알고 있습니다. 따라서 `1` - `10`밀리초 해상도의 시간 측정을 위한 인터페이스가 보장됩니다. 표준 `jiffies` 외에, 우리는 거의 `1193182`헤르츠의 [programmable interval timer](https://en.wikipedia.org/wiki/Programmable_interval_timer)틱 속도를 기반으로 하는 이전 파트의 `refined_jiffies`클럭 소스를 봤습니다. 따라서 `refined_jiffies`로 `1`마이크로 초 해상도에 관한 무언가를 얻을 수 있습니다. 이번에는 [나노 초](https://en.wikipedia.org/wiki/Nanosecond)로 주어진 클럭 소스의 타임 벨류 유닛을 위한 선호하는 선택을 합니다.

시간 간격 측정을 위한 더 정확한 기술의 가용성은 하드웨어에 따라 다릅니다. 우리는 `x86` 의존 타이머 하드웨어에 대해 조금 알고 있습니다. 그러나 각 아키텍처는 자체 타이머 하드웨어를 제공합니다. 이전에는 각 아키텍처가 이 목적을 위해 구현되었습니다. 이 문제의 해결책은 다양한 클럭 소스를 관리하고 타이머 인터럽트와 독립적인 공통 코드 프레임워크의 추상 레이어 및 관련 API입니다. 이 공통 코드 프레임워크는 `clocksource`프레임워크 입니다.

일반적인 timeofday와 클럭 소스 관리 프레임워크는 많은 timekeeping코드를 코드의 아키텍처 독립적인 부분으로 이동시켰으며, 아키텍처 의존적인 부분은 클럭소스의 저수준 하드웨어 부분을 정의하고 관리하는 것으로 축소되었습니다.  다른 하드웨어로 다른 아키텍처마다 시간 간격을 측정하려면 많은 자금이 필요하며 매우 복잡합니다. 서비스와 관련된 각 클럭의 구현은 개별 하드웨어 장치와 밀접하게 연관됐으며, 이해하는 것처럼 다른 아키텍처에서도 비슷한 구현이 발생합니다.

이 프레임워크 내에서, 각 클럭 소스는 단조롭게 증가하는 값으로 시간 표현을 유지해야 합니다. 우리가 리눅스 커널 코드에서 볼 수 있듯이, 나노 초는 이 시점에서 클럭 소스의 타임 벨류 유닛에 대한 가장 선호되는 선택입니다. 클럭 소스 프레임워크의 중요한 점은 사용자가 시스템을 구성하고 선택, 접근 및 다른 클럭 소스를 스케일링할 때 클록 함수를 지원하는 다양한 하드웨어 중에서 클럭 소스를 선택하는 것을 허용하는 것입니다.

클록 소스 구조체
--------------------------------------------------------------------------------

`clocksource`프레임워크의 기본은 [include/linux/clocksource.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/clocksource.h)헤더파일에 정의된 `clocksource`구조체입니다. 우리는 이미 이전 [파트](https://0xax.gitbooks.io/linux-insides/content/Timers/linux-timers-1.html)에서 `clocksource`구조체가 제공하는 몇 가지 필드를 봤습니다. 이 구조체의 전체 정의을 살펴보고 모든 필드를 설명하겠습니다:

```C
struct clocksource {
	cycle_t (*read)(struct clocksource *cs);
	cycle_t mask;
	u32 mult;
	u32 shift;
	u64 max_idle_ns;
	u32 maxadj;
#ifdef CONFIG_ARCH_CLOCKSOURCE_DATA
	struct arch_clocksource_data archdata;
#endif
	u64 max_cycles;
	const char *name;
	struct list_head list;
	int rating;
	int (*enable)(struct clocksource *cs);
	void (*disable)(struct clocksource *cs);
	unsigned long flags;
	void (*suspend)(struct clocksource *cs);
	void (*resume)(struct clocksource *cs);
#ifdef CONFIG_CLOCKSOURCE_WATCHDOG
	struct list_head wd_list;
	cycle_t cs_last;
	cycle_t wd_last;
#endif
	struct module *owner;
} ____cacheline_aligned;
```

우리는 이미 이전 파트에서 `clocksource`구조체의 첫 번째 필드를 봤습니다. 이것은 클럭 소스 프레임워크에서 선택한 최고의 카운터를 반환하는 `read`함수의 포인터입니다. 예를 들어 `jiffies_read`함수를 사용해 `jiffies`값을 읽습니다:

```C
static struct clocksource clocksource_jiffies = {
	...
	.read		= jiffies_read,
	...
}
```

여기서 `jiffies_read`을 반환합니다:

```C
static cycle_t jiffies_read(struct clocksource *cs)
{
	return (cycle_t) jiffies;
}
```

또는 `read_tsc`함수입니다:

```C
static struct clocksource clocksource_tsc = {
	...
    .read                   = read_tsc,
	...
};
```
[타임 스탬프 카운터](https://en.wikipedia.org/wiki/Time_Stamp_Counter)를 읽었습니다.

다음 필드는 비`64 bit`카운터와 카운터 값을 빼는데 특별한 오버플로 논리가 필요하지 않도록 보장해주는 `mask`입니다. `mask`필드 다음에 우리는 두 필드 `mult`와 `shifr`를 볼 수 있습니다. 이들은 각 클럭 소스에 특정한 타임 벨류를 변환하는 기능을 제공하는 수학 함수의 기초가 되는 필드입니다. 즉, 이 두 필드는 카운터의 추상 기계 타임 유닛을 나노 초로 변환하는데 도움이 됩니다.

이 두 필드 이후에 `64`비트 `max_idle_ns`필드는 클럭 소스가 허용하는 최대 대기 시간을 나노 초 단위로 나타냅니다.이 필드에는 `CONFIG_NO_HZ`커널 구성 옵션이 활성화된 리눅스 커널이 필요합니다. 이 커널 구성 옵션은 정규 타이머 틱(다른 파트에서 모든 설명을 볼 것입니다) 없이 리눅스 커널을 활성화합니다. 문제는 다이나믹 틱이 커널에 싱글 틱보다 긴 시간 동안 절전을 허용하며, 절전 시간에 제한도 없다는 것입니다. `max_idle_ns`필드는 이 절전 한계를 나타냅니다. 

`max_idle_ns` 다음 필드는  `mult`의 최대 조정 값인 `maxadj`필드입니다. 사이클을 나노 초로 변환하는 주요 공식:

```C
((u64) cycles * mult) >> shift;
```

`100%`정확하지는 않습니다. 대신 숫자는 가능한 한 나노 초에 가깝고, `maxadj`는 이를 수정하는데 도움이 되며, 클럭 소스 API가 조정됐을 때 오버플로 될 수 있는 `mult`값을 피하게 해줍니다. 다음 4개의 필드는 함수에 대한 포인터입니다:

* `enable` - 클럭 소스를 활성화하는 옵션 함수;
* `disable` - 클럭 소스를 비활성화하는 옵션 함수;
* `suspend` - 클럭 소스에 대한 일시 중단 함수;
* `resume` - 클럭 소스에 대한 다시 시작 함수;

다음 필드는 `max_cycles`로 이름에서 알 수 있듯이, 이 필드는 잠재적 오버플로 이전의 최대 사이클 값을 나타냅니다. 그리고 마지막 필드는 `owner`로 클럭 소스의 소유자인 커널 [모듈](https://en.wikipedia.org/wiki/Loadable_kernel_module)에 대한 참조를 나타냅니다. 이것이 전부입니다. 우리는 `clocksource`구조체의 모든 표준 필드를 살펴보았습니다. 그러나 `clocksource` 구조체의 일부 필드를 놓친 것을 알 수 있습니다. 누락된 모든 필드는 두 타입으로 나눌 수 있습니다: 첫 번째 타입은 이미 알고 있습니다. 예를 들어, `clocksource`의 이름을 나타내는 `name`필드에서, `rating`필드는 리눅스 커널에이 최상의 클럭 소스 등을 선택하는데 도움이 됩니다. 두 번째 타입은, 다른 리눅스 커널 구성 옵션에 종속적인 필드입니다. 이 필드들을 살펴봅시다.

첫 번째 필드는 `archdata`입니다. 이 필드는 `arch_clocksource_data`타입을 가졌으며`CONFIG_ARCH_CLOCKSOURCE_DATA` 커널 구성 옵션에 따라 다릅니다. 이 필드는 현재 [x86](https://en.wikipedia.org/wiki/X86) 및 [IA64](https://en.wikipedia.org/wiki/IA-64)에만 해당합니다. 또한 필드 이름에서 알 수 있듯이, 클럭 소스에 대한 아키텍처 특정 데이터를 나타냅니다. 예를 들어, `vDSO` 클럭 모드를 나타냅니다:

```C
struct arch_clocksource_data {
    int vclock_mode;
};
```
 
`x86`아키텍처를 위합니다. `vDSO`클럭 모드의 위치는 다음 중 하나가 될 수 있습니다:

```C
#define VCLOCK_NONE 0
#define VCLOCK_TSC  1
#define VCLOCK_HPET 2
#define VCLOCK_PVCLOCK 3
```

마지막 세 필드는 `CONFIG_CLOCKSOURCE_WATCHDOG` 커널 구성 옵션에 따르는 `wd_list`, `cs_last`, `wd_last`입니다. 우선 `watchdog`가 무엇인지 이해해봅시다. 간단히 말하면, watchdog는 컴퓨터 오작동을 감지하고 복구하는데 사용되는 타이머입니다. 이 세 필드는 `clocksource`프레임워크에서 사용하는 데이터와 관련된 watchdog를 포함합니다. 리눅스 커널 소스 코드를 grep하면 [arch/x86/KConfig](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/Kconfig#L54)커널 구성 파일에서만 `CONFIG_CLOCKSOURCE_WATCHDOG` 커널 구성 옵션을 포함한 것을 볼 수 있습니다. 왜 [watchdog](https://en.wikipedia.org/wiki/Watchdog_timer)에서 `x86` 및 `x86_64`이 필요할까요? 당신은 이미 모든 `x86`프로세서가 특별한 64비트 레지스터 [타임 스탬프 카운터](https://en.wikipedia.org/wiki/Time_Stamp_Counter)를 가진 것을 알 것입니다. 이 레지스터는 리셋 이후의 [cycles](https://en.wikipedia.org/wiki/Clock_rate)수를 포함합니다. 때때로 타임 스탬프 카운터는 다른 클럭 소스를 확인해야합니다. 우리는 이 파트에서 `watchdog`타이머의 초기화는 보지 않을 것입니다. 그 전에 타이머에 대해 더 배워야 합니다.

그것이 전부입니다. 이 순간부터 우리는 `clocksource`구조체의 모든 필드를 압니다. 이 지식은 `clocksource`프레임워크 내부를 배우는 것을 도와줄 것입니다.

새로운 클럭 소스 등록
--------------------------------------------------------------------------------

우리는 이전 [파트](https://0xax.gitbooks.io/linux-insides/content/Timers/linux-timers-1.html)의 `clocksource`프레임워크에서 하나의 함수만을 봤습니다. 이 함수는 `__clocksource_register`입니다. 이 함수는 [include/linux/clocksource.h](https://github.com/torvalds/linux/tree/master/include/linux/clocksource.h)헤더파일에서 정의되었으며 이름에서 알 수 있듯이, 이 함수의 중요한 점은 새로운 클럭 소스를 등록하는 것입니다. `__clocksource_register`함수의 구현을 살펴보면, `__clocksource_register_scale`함수의 호출과 그 결과의 반환을 볼 수 있습니다:

```C
static inline int __clocksource_register(struct clocksource *cs)
{
	return __clocksource_register_scale(cs, 1, 0);
}
```

`__clocksource_register_scale`함수의 구현을 보기 전에, `clocksource`에서 새로운 클럭 소스 등록을 위한 추가 API를 제공하는 것을 볼 수 있습니다:

```C
static inline int clocksource_register_hz(struct clocksource *cs, u32 hz)
{
        return __clocksource_register_scale(cs, 1, hz);
}

static inline int clocksource_register_khz(struct clocksource *cs, u32 khz)
{
        return __clocksource_register_scale(cs, 1000, khz);
}
```

그리고 이 모든 함수는 동일합니다. 이들은 `__clocksource_register_scale`함수의 값을 반환하지만 다른 매개 변수 설정을 사용합니다. `__clocksource_register_scale`는 [kernel/time/clocksource.c](https://github.com/torvalds/linux/tree/master/kernel/time/clocksource.c)소스 코드 파일에서 정의되었습니다. 함수들 사이의 차이를 이해하기 위해 `clocksource_register_khz`함수의 매개변수를 살펴봅시다. 보시다시피, 이 함수는 세 개의 매개변수를 가집니다:

* `cs` - 설치될 클럭 소스;
* `scale` - 클러 소스의 스케일 요소.다시 말해, 이 매개변수의 값을 주파수에 곱하면 클럭 소스의 `hz`를 얻을 수 있습니다;
* `freq` - 클럭 소스 주파수를 스케일로 나눈 값.

이제 `__clocksource_register_scale`함수의 구현을 살펴봅시다:

```C
int __clocksource_register_scale(struct clocksource *cs, u32 scale, u32 freq)
{
        __clocksource_update_freq_scale(cs, scale, freq);
        mutex_lock(&clocksource_mutex);
        clocksource_enqueue(cs);
        clocksource_enqueue_watchdog(cs);
        clocksource_select();
        mutex_unlock(&clocksource_mutex);
        return 0;
}
```

우선 `__clocksource_register_scale`함수가 동일한 소스 코드 파일에서 정의된 `__clocksource_update_freq_scale`함수에서 시작하고 주어진 클럭 소스를 새로운 주파수로 업데이트 하는 것을 볼 수 있습니다. 이 함수의 구현을 살펴봅시다. 첫 번째 단계ㄹ 우리는 주어진 주파수를 확인하고 `0`으로 전달되지 않으면, 주어진 클럭 소스에 대한 `mult` 및 `shift` 매개변수를 계산해야 합니다. 왜 `frequency`의 값을 확인해야 하는 걸까요? 실제로 이것이 0이 될 수 있기 때문입니다.  `__clocksource_register`함수의 구현을 주의깊게 보면, `frequency`가 `0`으로 전달 되는 것을 눈치 챌 수 있을 것입니다. 우리는 스스로 정의된 `mult` 및 `shift`매개변수를 가진 일부 클럭 소스에 대해서만 이를 수행할 것입니다. 이전 [파트](https://0xax.gitbooks.io/linux-insides/content/Timers/linux-timers-1.html)를 보면 `jiffies`를 위한 `mult` 및 `shift`의 계산을 볼 수 있습니다. `__clocksource_update_freq_scale`함수는 다른 클럭 소스를 위한 우리의 클럭 소스를 위해 작동합니다.

따라서 `__clocksource_update_freq_scale`함수의 시작에서 우리는 `frequency`매개변수의 값을 확인하고 0이 아니면 주어진 클럭 소스를 위한 `mult` 및 `shift`를 계산해야합니다. `mult`와 `shift`의 계산을 살펴봅시다:

```C
void __clocksource_update_freq_scale(struct clocksource *cs, u32 scale, u32 freq)
{
        u64 sec;

		if (freq) {
             sec = cs->mask;
             do_div(sec, freq);
             do_div(sec, scale);

             if (!sec)
                   sec = 1;
             else if (sec > 600 && cs->mask > UINT_MAX)
                   sec = 600;
 
             clocks_calc_mult_shift(&cs->mult, &cs->shift, freq,
                                    NSEC_PER_SEC / scale, sec * scale);
	    }
	    ...
        ...
        ...
}
```

Here we can see calculation of the maximum number of seconds which we can run before a clock source counter will overflow. First of all we fill the `sec` variable with the value of a clock source mask. Remember that a clock source's mask represents maximum amount of bits that are valid for the given clock source. After this, we can see two division operations. At first we divide our `sec` variable on a clock source frequency and then on scale factor. The `freq` parameter shows us how many timer interrupts will be occurred in one second. So, we divide `mask` value that represents maximum number of a counter (for example `jiffy`) on the frequency of a timer and will get the maximum number of seconds for the certain clock source. The second division operation will give us maximum number of seconds for the certain clock source depends on its scale factor which can be `1` hertz or `1` kilohertz (10^3 Hz).


After we have got maximum number of seconds, we check this value and set it to `1` or `600` depends on the result at the next step. These values is maximum sleeping time for a clocksource in seconds. In the next step we can see call of the `clocks_calc_mult_shift`. Main point of this function is calculation of the `mult` and `shift` values for a given clock source. In the end of the `__clocksource_update_freq_scale` function we check that just calculated `mult` value of a given clock source will not cause overflow after adjustment, update the `max_idle_ns` and `max_cycles` values of a given clock source with the maximum nanoseconds that can be converted to a clock source counter and print result to the kernel buffer:

```C
pr_info("%s: mask: 0x%llx max_cycles: 0x%llx, max_idle_ns: %lld ns\n",
	cs->name, cs->mask, cs->max_cycles, cs->max_idle_ns);
```

that we can see in the [dmesg](https://en.wikipedia.org/wiki/Dmesg) output:

```
$ dmesg | grep "clocksource:"
[    0.000000] clocksource: refined-jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 1910969940391419 ns
[    0.000000] clocksource: hpet: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 133484882848 ns
[    0.094084] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 1911260446275000 ns
[    0.205302] clocksource: acpi_pm: mask: 0xffffff max_cycles: 0xffffff, max_idle_ns: 2085701024 ns
[    1.452979] clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x7350b459580, max_idle_ns: 881591204237 ns
```

After the `__clocksource_update_freq_scale` function will finish its work, we can return back to the `__clocksource_register_scale` function that will register new clock source. We can see the call of the following three functions:

```C
mutex_lock(&clocksource_mutex);
clocksource_enqueue(cs);
clocksource_enqueue_watchdog(cs);
clocksource_select();
mutex_unlock(&clocksource_mutex);
```

Note that before the first will be called, we lock the `clocksource_mutex` [mutex](https://en.wikipedia.org/wiki/Mutual_exclusion). The point of the `clocksource_mutex` mutex is to protect `curr_clocksource` variable which represents currently selected `clocksource` and `clocksource_list` variable which represents list that contains registered `clocksources`. Now, let's look on these three functions.

The first `clocksource_enqueue` function and other two defined in the same source code [file](https://github.com/torvalds/linux/tree/master/kernel/time/clocksource.c). We go through all already registered `clocksources` or in other words we go through all elements of the `clocksource_list` and tries to find best place for a given `clocksource`:

```C
static void clocksource_enqueue(struct clocksource *cs)
{
	struct list_head *entry = &clocksource_list;
	struct clocksource *tmp;

	list_for_each_entry(tmp, &clocksource_list, list)
		if (tmp->rating >= cs->rating)
			entry = &tmp->list;
	list_add(&cs->list, entry);
}
```

In the end we just insert new clocksource to the `clocksource_list`. The second function - `clocksource_enqueue_watchdog` does almost the same that previous function, but it inserts new clock source to the `wd_list` depends on flags of a clock source and starts new [watchdog](https://en.wikipedia.org/wiki/Watchdog_timer) timer. As I already wrote, we will not consider `watchdog` related stuff in this part but will do it in next parts.

The last function is the `clocksource_select`. As we can understand from the function's name, main point of this function - select the best `clocksource` from registered clocksources. This function consists only from the call of the function helper:

```C
static void clocksource_select(void)
{
	return __clocksource_select(false);
}
```

Note that the `__clocksource_select` function takes one parameter (`false` in our case). This [bool](https://en.wikipedia.org/wiki/Boolean_data_type) parameter shows how to traverse the `clocksource_list`. In our case we pass `false` that is meant that we will go through all entries of the `clocksource_list`. We already know that `clocksource` with the best rating will the first in the `clocksource_list` after the call of the `clocksource_enqueue` function, so we can easily get it from this list. After we found a clock source with the best rating, we switch to it:

```C
if (curr_clocksource != best && !timekeeping_notify(best)) {
	pr_info("Switched to clocksource %s\n", best->name);
	curr_clocksource = best;
}
```

The result of this operation we can see in the `dmesg` output:

```
$ dmesg | grep Switched
[    0.199688] clocksource: Switched to clocksource hpet
[    2.452966] clocksource: Switched to clocksource tsc
```

Note that we can see two clock sources in the `dmesg` output (`hpet` and `tsc` in our case). Yes, actually there can be many different clock sources on a particular hardware. So the Linux kernel knows about all registered clock sources and switches to a clock source with a better rating each time after registration of a new clock source.

If we will look on the bottom of the [kernel/time/clocksource.c](https://github.com/torvalds/linux/tree/master/kernel/time/clocksource.c) source code file, we will see that it has [sysfs](https://en.wikipedia.org/wiki/Sysfs) interface. Main initialization occurs in the `init_clocksource_sysfs` function which will be called during device `initcalls`. Let's look on the implementation of the `init_clocksource_sysfs` function:

```C
static struct bus_type clocksource_subsys = {
	.name = "clocksource",
	.dev_name = "clocksource",
};

static int __init init_clocksource_sysfs(void)
{
	int error = subsys_system_register(&clocksource_subsys, NULL);

	if (!error)
		error = device_register(&device_clocksource);
	if (!error)
		error = device_create_file(
				&device_clocksource,
				&dev_attr_current_clocksource);
	if (!error)
		error = device_create_file(&device_clocksource,
					   &dev_attr_unbind_clocksource);
	if (!error)
		error = device_create_file(
				&device_clocksource,
				&dev_attr_available_clocksource);
	return error;
}
device_initcall(init_clocksource_sysfs);
```

First of all we can see that it registers a `clocksource` subsystem with the call of the `subsys_system_register` function. In other words, after the call of this function, we will have following directory:

```
$ pwd
/sys/devices/system/clocksource
```

After this step, we can see registration of the `device_clocksource` device which is represented by the following structure:

```C
static struct device device_clocksource = {
	.id	= 0,
	.bus	= &clocksource_subsys,
};
```

and creation of three files:

* `dev_attr_current_clocksource`;
* `dev_attr_unbind_clocksource`;
* `dev_attr_available_clocksource`.

These files will provide information about current clock source in the system, available clock sources in the system and interface which allows to unbind the clock source.

After the `init_clocksource_sysfs` function will be executed, we will be able find some information about available clock sources in the:

```
$ cat /sys/devices/system/clocksource/clocksource0/available_clocksource 
tsc hpet acpi_pm 
```

Or for example information about current clock source in the system:

```
$ cat /sys/devices/system/clocksource/clocksource0/current_clocksource 
tsc
```

In the previous part, we saw API for the registration of the `jiffies` clock source, but didn't dive into details about the `clocksource` framework. In this part we did it and saw implementation of the new clock source registration and selection of a clock source with the best rating value in the system. Of course, this is not all API that `clocksource` framework provides. There a couple additional functions like `clocksource_unregister` for removing given clock source from the `clocksource_list` and etc. But I will not describe this functions in this part, because they are not important for us right now. Anyway if you are interesting in it, you can find it in the [kernel/time/clocksource.c](https://github.com/torvalds/linux/tree/master/kernel/time/clocksource.c).

That's all.

Conclusion
--------------------------------------------------------------------------------

This is the end of the second part of the chapter that describes timers and timer management related stuff in the Linux kernel. In the previous part got acquainted with the following two concepts: `jiffies` and `clocksource`. In this part we saw some examples of the `jiffies` usage and knew more details about the `clocksource` concept.

If you have questions or suggestions, feel free to ping me in twitter [0xAX](https://twitter.com/0xAX), drop me [email](anotherworldofworld@gmail.com) or just create [issue](https://github.com/0xAX/linux-insides/issues/new).

**Please note that English is not my first language and I am really sorry for any inconvenience. If you found any mistakes please send me PR to [linux-insides](https://github.com/0xAX/linux-insides).**

Links
-------------------------------------------------------------------------------

* [x86](https://en.wikipedia.org/wiki/X86)
* [x86_64](https://en.wikipedia.org/wiki/X86-64)
* [uptime](https://en.wikipedia.org/wiki/Uptime)
* [Ensoniq Soundscape Elite](https://en.wikipedia.org/wiki/Ensoniq_Soundscape_Elite)
* [RTC](https://en.wikipedia.org/wiki/Real-time_clock)
* [interrupts](https://en.wikipedia.org/wiki/Interrupt)
* [IBM PC](https://en.wikipedia.org/wiki/IBM_Personal_Computer)
* [programmable interval timer](https://en.wikipedia.org/wiki/Programmable_interval_timer)
* [Hz](https://en.wikipedia.org/wiki/Hertz)
* [nanoseconds](https://en.wikipedia.org/wiki/Nanosecond)
* [dmesg](https://en.wikipedia.org/wiki/Dmesg)
* [time stamp counter](https://en.wikipedia.org/wiki/Time_Stamp_Counter)
* [loadable kernel module](https://en.wikipedia.org/wiki/Loadable_kernel_module)
* [IA64](https://en.wikipedia.org/wiki/IA-64)
* [watchdog](https://en.wikipedia.org/wiki/Watchdog_timer)
* [clock rate](https://en.wikipedia.org/wiki/Clock_rate)
* [mutex](https://en.wikipedia.org/wiki/Mutual_exclusion)
* [sysfs](https://en.wikipedia.org/wiki/Sysfs)
* [previous part](https://0xax.gitbooks.io/linux-insides/content/Timers/linux-timers-1.html)
