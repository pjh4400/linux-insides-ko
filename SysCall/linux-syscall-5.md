어떻게 `open` 시스템 콜 작업을 수행하나요?
--------------------------------------------------------------------------------

소개
--------------------------------------------------------------------------------

이것은 리눅스 커널의 [시스템 콜](https://en.wikipedia.org/wiki/System_call) 메커니즘을 설명하는 이 장의 다섯 번째 부분입니다. 이 장의 이전 부분에서는 이 메커니즘을 일반적으로 설명했습니다. 이제 Linux 커널에서 다른 시스템 호출의 구현을 설명하려고 합니다. 이 장의 이전 부분과 이 책의 다른 장의 부분은 사용자 공간에서 희미하게 보이거나 완전히 보이지 않는 Linux 커널의 대부분을 설명합니다. 그러나 리눅스 커널 코드는 그 자체가 아닙니다. 광대 한 리눅스 커널 코드는 우리 코드에 능력을 제공합니다. 리눅스 커널로 인해 우리 프로그램은 파일을 읽고 쓸 수 있으며 섹터, 트랙 및 디스크 구조의 다른 부분에 대해 전혀 알지 못하고도 네트워크를 통해 데이터를 보낼 수 있으며 수동으로 캡슐화 된 네트워크 패킷을 만들 지 않아도 됩니다.

당신의 경우 어떤지 모르겠지만 운영 체제가 작동하는 방법뿐만 아니라 소프트웨어가 어떻게 상호 작용하는지는 흥미롭습니다. 아시다시피, 우리의 프로그램은 [시스템 호출](https://en.wikipedia.org/wiki/System_call)이라는 특수 메커니즘을 통해 커널과 상호 작용합니다. 그래서 저는 `읽기`, `쓰기`, `열기`, `닫기`, `dup` 등과 같은 매일 우리가 사용하는 시스템 호출의 구현과 동작을 설명하는 일련의 부분을 작성하기로 결정했습니다 .

[open](http://man7.org/linux/man-pages/man2/open.2.html) 시스템 호출에 대한 설명부터 시작하기로 결정했습니다. 적어도 하나의 `C` 프로그램을 작성했다면 파일로 다른 조작을 읽거나 쓰거나 실행하기 전에 `open` 함수로 파일을 열어야한다는 것을 알아야합니다.

```C
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char *argv) {
        int fd = open("test", O_RDONLY);

        if fd < 0 {
                perror("Opening of the file is failed\n");
        }
        else {
                printf("file sucessfully opened\n");
        }

        close(fd); 
        return 0;
}
```

이 경우 열기는 표준 라이브러리의 함수이지만 시스템 호출은 아닙니다. 표준 라이브러리는 우리에게 관련 시스템 호출을 호출합니다. `open` 호출은 프로세스 내에서 열린 파일과 관련된 고유 번호 인 [file descriptor](https://en.wikipedia.org/wiki/File_descriptor)를 반환합니다. 이제 `open` 호출의 결과로 파일을 열고 파일 설명자를 얻었으므로 이 파일과 상호 작용을 시작할 수 있습니다. 프로세스에 의해 열린 파일의 목록은 [proc](https://en.wikipedia.org/wiki/Procfs) 파일 시스템을 통해 이용할 수 있습니다 :

```
$ sudo ls /proc/1/fd/

0  10  12  14  16  2   21  23  25  27  29  30  32  34  36  38  4   41  43  45  47  49  50  53  55  58  6   61  63  67  8
1  11  13  15  19  20  22  24  26  28  3   31  33  35  37  39  40  42  44  46  48  5   51  54  57  59  60  62  65  7   9
```

이 게시물의 사용자 공간보기에서 `오픈` 루틴에 대한 자세한 내용은 설명하지 않지만 대부분 커널 측에서 설명합니다. 잘 모른다면 [man page](http://man7.org/linux/man-pages/man2/open.2.html)에서 더 많은 정보를 얻을 수 있습니다.

이제 시작하겠습니다.

오픈 시스템콜의 정의
--------------------------------------------------------------------------------

[linux-insides](https:0xax.gitbooks.io/linux-insides/content/index.html)의 [네 번째 파트](https://github.com/0xAX/linux-insides/blob/master/SysCall/linux-syscall-4.md)를 읽은 경우  책에서 시스템 호출은`SYSCALL_DEFINE` 매크로의 도움으로 정의된다는 것을 알아야합니다. 따라서 `open`시스템 콜도 예외는 아닙니다.

`open` 시스템 콜의 정의는 [fs/open.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/open.c) 소스 코드 파일에 있으며 꽤 작게 보입니다. 

첫 번째보기 :

```C
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	if (force_o_largefile())
		flags |= O_LARGEFILE;

	return do_sys_open(AT_FDCWD, filename, flags, mode);
}
```

짐작 하시겠지만, [동일](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/open.c) 소스 코드 파일의 `do_sys_open` 기능이 주요 작업을 수행합니다. 그러나 이 함수가 호출되기 전에, `open` 시스템 호출의 구현이 시작되는 `if` 절을 고려해 봅시다 :

```C
if (force_o_largefile())
	flags |= O_LARGEFILE;
```

여기서 우리는 `force_o_largefile()`이 true를 반환 할 경우에 `O_LARGEFILE` 플래그를 `open` 시스템 콜에 전달 된 플래그에 적용합니다.
`O_LARGEFILE`은 무엇입니까? 우리는 `open(2)` 시스템 콜에 대한 [man page](http://man7.org/linux/man-pages/man2/open.2.html)에서 이것을 읽을 수 있습니다 :

> O_LARGEFILE
>
> (LFS) 크기를 off_t로 표현할 수 없지만 off64_t로 표현할 수있는 파일을 열 수 있습니다.

[GNU C Library Reference Manual](https://www.gnu.org/software/libc/manual/html_mono/libc.html#File-Position-Primitive)에서 읽을 수있는 바와 같이 :

> off_t
>
> 파일 크기를 나타내는 데 사용되는 부호있는 정수 유형입니다.
> GNU C 라이브러리에서이 유형은 int보다 좁지 않습니다.
> 소스가 _FILE_OFFSET_BITS == 64로 컴파일 된 경우
> type은 투명하게 off64_t로 대체됩니다.

그리고

> off64_t
>
>이 유형은 off_t와 유사하게 사용됩니다. 차이점은
> off_t 유형이 32 비트 인 32 비트 시스템에서도
> off64_t는 64 비트이므로 최대 2 ^ 63 바이트의 파일을 처리 할 수 있습니다.
> 길이. _FILE_OFFSET_BITS == 64로 컴파일 할 때이 유형
>는 off_t라는 이름으로 제공됩니다.

따라서 `off_t`, `off64_t` 및 `O_LARGEFILE`이 대략 파일 크기라고 추측하기 어렵지 않습니다. 리눅스 커널의 경우, `O_LARGEFILE`은 호출자가 파일을 여는 동안 `O_LARGEFILE` 플래그를 지정하지 않은 경우 32 비트 시스템에서 큰 파일을 열 수 없도록하는 데 사용됩니다. 64 비트 시스템에서는 오픈 시스템 콜에서 이 플래그를 사용합니다. 그리고 [include/linux/fcntl.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/fcntl.h#L7) 리눅스 커널 헤더 파일의 `force_o_largefile` 매크로는 이것을 확인합니다 :

```C
#ifndef force_o_largefile
#define force_o_largefile() (BITS_PER_LONG != 32)
#endif
```

이 매크로는 예를 들어 [IA-64](https://en.wikipedia.org/wiki/IA-64) 아키텍처와 같이 아키텍처에 따라 다를 수 있지만이 경우에는 [x86_64](https://en.wikipedia.org/wiki/X86-64)는 `force_o_largefile`의 정의를 제공하지 않으며 [include/linux/fcntl.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/fcntl.h#L7)에서 사용됩니다..

따라서 우리가 알 수 있듯이 `force_o_largefile`은 [x86_64](https://en.wikipedia.org/wiki/X86-64) 아키텍처의 경우 `true` 값으로 확장되는 매크로 일뿐입니다. 64 비트 아키텍처를 고려할 때 `force_o_largefile`은 `true`로 확장되고 `O_LARGEFILE` 플래그는 `open` 시스템 콜에 전달 된 플래그 세트에 추가됩니다.

이제 우리는 `O_LARGEFILE` 플래그와 `force_o_largefile` 매크로의 의미를 고려 했으므로 `do_sys_open` 함수의 구현을 고려할 수 있습니다. 위에서 쓴 것처럼이 함수는 [동일](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/open.c) 소스 코드 파일에 정의되어 있으며 다음과 같습니다.

```C
long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
	struct open_flags op;
	int fd = build_open_flags(flags, mode, &op);
	struct filename *tmp;

	if (fd)
		return fd;

	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	fd = get_unused_fd_flags(flags);
	if (fd >= 0) {
		struct file *f = do_filp_open(dfd, tmp, &op);
		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			fsnotify_open(f);
			fd_install(fd, f);
		}
	}
	putname(tmp);
	return fd;
}
```

이제 `do_sys_open`이 단계별로 작동하는 방식을 이해해봅시다

open(2) flags
--------------------------------------------------------------------------------

알다시피 `open` 시스템 호출은 파일 열기를 제어하는 두 번째 인수로`flags`를, 파일이 작성된 경우 파일의 권한을 지정하는 세 번째 인수로 mode를 사용합니다. `do_sys_open` 함수는`build_open_flags` 함수의 호출에서 시작하는데,이 함수는 주어진 플래그 세트가 유효한지 확인하고 플래그와 모드의 다른 조건을 처리합니다.

`build_open_flags`의 구현을 살펴 봅시다. 이 함수는 [동일](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/open.c) 커널 파일에 정의되어 있으며 세 가지 인수를 사용합니다.

* flags - 파일 열기를 제어하는 플래그.
* mode - 새로 작성된 파일에 대한 권한

마지막 인수 인 `op`는 `open_flags` 구조체로 표현됩니다 :

```C
struct open_flags {
        int open_flag;
        umode_t mode;
        int acc_mode;
        int intent;
        int lookup_flags;
};
```

이는 [fs/internal.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/internal.h#L99) 헤더 파일에 정의되어 있으며 플래그 및 내부 커널 목적을 위한 액세스 모입니다. 이미 알고 있듯이 `build_open_flags` 함수의 주요 목표는 이 구조체의 인스턴스를 채우는 것입니다.

`build_open_flags` 함수의 구현은 지역 변수의 정의에서 시작하며 그중 하나는 다음과 같습니다.

```C
int acc_mode = ACC_MODE(flags);
```

이 지역 변수는 액세스 모드를 나타내며 초기 값은 확장 된 `ACC_MODE` 매크로의 값과 같습니다. 이 매크로는 [include/linux/ fs.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/fs.h)에 정의되어 있으며 매우 흥미로워 보입니다.

```C
#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define O_ACCMODE   00000003
```

`"\004\002\006\006"`는 4 개의 문자로 구성된 배열입니다.

```
"\004\002\006\006" == {'\004', '\002', '\006', '\006'}
```

따라서, `ACC_MODE` 매크로는 `[(x) & O_ACCMODE]` 인덱스에 의해 이 배열에 대한 접근으로 확장됩니다. 방금 보았 듯이 `O_ACCMODE`는 `00000003`입니다. `x & O_ACCMODE`를 적용하면 `읽기`, `쓰기`또는 `읽기/쓰기` 액세스 모드를 나타내는 최하위 비트 2 개를 가져옵니다.

```C
#define O_RDONLY        00000000
#define O_WRONLY        00000001
#define O_RDWR          00000002
```

계산 된 인덱스에 의해 배열에서 값을 얻은 후, `ACC_MODE`는 `MAY_WRITE`, `MAY_READ`및 기타 정보를 보유 할 파일의 액세스 모드 마스크로 확장됩니다.

초기 액세스 모드를 계산 한 후 다음과 같은 상태가 나타날 수 있습니다.

```C
if (flags & (O_CREAT | __O_TMPFILE))
	op->mode = (mode & S_IALLUGO) | S_IFREG;
else
	op->mode = 0;
```

Here we reset permissions in `open_flags` instance if a opened file wasn't temporary and wasn't open for creation. This is because:

> if  neither O_CREAT nor O_TMPFILE is specified, then mode is ignored.

In other case if `O_CREAT` or `O_TMPFILE` were passed we canonicalize it to a regular file because a directory should be created with the [opendir](http://man7.org/linux/man-pages/man3/opendir.3.html) system call.

At the next step we check that a file is not tried to be opened via [fanotify](http://man7.org/linux/man-pages/man7/fanotify.7.html) and without the `O_CLOEXEC` flag:

```C
flags &= ~FMODE_NONOTIFY & ~O_CLOEXEC;
```

We do this to not leak a [file descriptor](https://en.wikipedia.org/wiki/File_descriptor). By default, the new file descriptor is set to remain open across an `execve` system call, but the `open` system call supports `O_CLOEXEC` flag that can be used to change this default behaviour. So we do this to prevent leaking of a file descriptor when one thread opens a file to set `O_CLOEXEC` flag and in the same time the second process does a [fork](https://en.wikipedia.org/wiki/Fork_\(system_call\)) + [execve](https://en.wikipedia.org/wiki/Exec_\(system_call\)) and as you may remember that child will have copies of the parent's set of open file descriptors.

At the next step we check that if our flags contains `O_SYNC` flag, we apply `O_DSYNC` flag too:

```
if (flags & __O_SYNC)
	flags |= O_DSYNC;
```

The `O_SYNC` flag guarantees that the any write call will not return before all data has been transferred to the disk. The `O_DSYNC` is like `O_SYNC` except that there is no requirement to wait for any metadata (like `atime`, `mtime` and etc.) changes will be written. We apply `O_DSYNC` in a case of `__O_SYNC` because it is implemented as `__O_SYNC|O_DSYNC` in the Linux kernel.

After this we must be sure that if a user wants to create temporary file, the flags should contain `O_TMPFILE_MASK` or in other words it should contain or `O_CREAT` or `O_TMPFILE` or both and also it should be writeable:

```C
if (flags & __O_TMPFILE) {
	if ((flags & O_TMPFILE_MASK) != O_TMPFILE)
		return -EINVAL;
	if (!(acc_mode & MAY_WRITE))
		return -EINVAL;
} else if (flags & O_PATH) {
       	flags &= O_DIRECTORY | O_NOFOLLOW | O_PATH;
        acc_mode = 0;
}
```

as it is written in in the manual page:

> O_TMPFILE  must  be  specified  with one of O_RDWR or O_WRONLY

If we didn't pass `O_TMPFILE` for creation of a temporary file, we check the `O_PATH` flag at the next condition. The `O_PATH` flag allows us to obtain a file descriptor that may be used for two following purposes:

* to indicate a location in the filesystem tree;
* to perform operations that act purely at the file descriptor level.

So, in this case the file itself is not opened, but operations like `dup`, `fcntl` and other can be used. So, if all file content related operations like `read`, `write` and other are not permitted, only `O_DIRECTORY | O_NOFOLLOW | O_PATH` flags can be used. We have finished with flags for this moment in the `build_open_flags` for this moment and we may fill our `open_flags->open_flag` with them:

```C
op->open_flag = flags;
```

Now we have filled `open_flag` field which represents flags that will control opening of a file and `mode` that will represent `umask` of a new file if we open file for creation. There are still to fill last flags in the our `open_flags` structure. The next is `op->acc_mode` which represents access mode to a opened file. We already filled the `acc_mode` local variable with the initial value at the beginning of the `build_open_flags` and now we check last two flags related to access mode:

```C
if (flags & O_TRUNC)
        acc_mode |= MAY_WRITE;
if (flags & O_APPEND)
	acc_mode |= MAY_APPEND;
op->acc_mode = acc_mode;
```

These flags are - `O_TRUNC` that will truncate an opened file to length `0` if it existed before we open it and the `O_APPEND` flag allows to open a file in `append mode`. So the opened file will be appended during write but not overwritten.

The next field of the `open_flags` structure is - `intent`. It allows us to know about our intention or in other words what do we really want to do with file, open it, create, rename it or something else. So we set it to zero if our flags contains the `O_PATH` flag as we can't do anything related to a file content with this flag:

```C
op->intent = flags & O_PATH ? 0 : LOOKUP_OPEN;
```

or just to `LOOKUP_OPEN` intention. Additionally we set `LOOKUP_CREATE` intention if we want to create new file and to be sure that a file didn't exist before with `O_EXCL` flag:

```C
if (flags & O_CREAT) {
	op->intent |= LOOKUP_CREATE;
	if (flags & O_EXCL)
		op->intent |= LOOKUP_EXCL;
}
```

The last flag of the `open_flags` structure is the `lookup_flags`:

```C
if (flags & O_DIRECTORY)
	lookup_flags |= LOOKUP_DIRECTORY;
if (!(flags & O_NOFOLLOW))
	lookup_flags |= LOOKUP_FOLLOW;
op->lookup_flags = lookup_flags;

return 0;
```

We fill it with `LOOKUP_DIRECTORY` if we want to open a directory and `LOOKUP_FOLLOW` if we don't want to follow (open) [symlink](https://en.wikipedia.org/wiki/Symbolic_link). That's all. It is the end of the `build_open_flags` function. The `open_flags` structure is filled with modes and flags for a file opening and we can return back to the `do_sys_open`.

Actual opening of a file
--------------------------------------------------------------------------------

At the next step after `build_open_flags` function is finished and we have formed flags and modes for our file we should get the `filename` structure with the help of the `getname` function by name of a file which was passed to the `open` system call:

```C
tmp = getname(filename);
if (IS_ERR(tmp))
	return PTR_ERR(tmp);
```

The `getname` function is defined in the [fs/namei.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/namei.c) source code file and looks:

```C
struct filename *
getname(const char __user * filename)
{
        return getname_flags(filename, 0, NULL);
}
```

So, it just calls the `getname_flags` function and returns its result. The main goal of the `getname_flags` function is to copy a file path given from userland to kernel space. The `filename` structure is defined in the [include/linux/fs.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/fs.h) linux kernel header file and contains following fields:

* name - pointer to a file path in kernel space;
* uptr - original pointer from userland;
* aname - filename from [audit](https://linux.die.net/man/8/auditd) context;
* refcnt - reference counter;
* iname - a filename in a case when it will be less than `PATH_MAX`.

As I already wrote above, the main goal of the `getname_flags` function is to copy name of a file which was passed to the `open` system call from user space to kernel space with the strncpy_from_user function. The next step after a filename will be copied to kernel space is getting of new non-busy file descriptor:

```C
fd = get_unused_fd_flags(flags);
```

The `get_unused_fd_flags` function takes table of open files of the current process, minimum (`0`) and maximum (`RLIMIT_NOFILE`) possible number of a file descriptor in the system and flags that we have passed to the `open` system call and allocates file descriptor and mark it busy in the file descriptor table of the current process. The `get_unused_fd_flags` function sets or clears the `O_CLOEXEC` flag depends on its state in the passed flags.

The last and main step in the `do_sys_open` is the `do_filp_open` function:

```C
struct file *f = do_filp_open(dfd, tmp, &op);

if (IS_ERR(f)) {
	put_unused_fd(fd);
	fd = PTR_ERR(f);
} else {
	fsnotify_open(f);
	fd_install(fd, f);
}
```

The main goal of this function is to resolve given path name into `file` structure which represents an opened file of a process. If something going wrong and execution of the `do_filp_open` function will be failed, we should free new file descriptor with the `put_unused_fd` or in other way the `file` structure returned by the `do_filp_open` will be stored in the file descriptor table of the current process.

Now let's take a short look at the implementation of the `do_filp_open` function. This function is defined in the [fs/namei.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/namei.c) linux kernel source code file and starts from initialization of the `nameidata` structure. This structure will provide a link to a file [inode](https://en.wikipedia.org/wiki/Inode). Actually this is one of the main point of the `do_filp_open` function to acquire an `inode` by the filename given to `open` system call. After the `nameidata` structure will be initialized, the `path_openat` function will be called:

```C
filp = path_openat(&nd, op, flags | LOOKUP_RCU);

if (unlikely(filp == ERR_PTR(-ECHILD)))
	filp = path_openat(&nd, op, flags);
if (unlikely(filp == ERR_PTR(-ESTALE)))
	filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
```

Note that it is called three times. Actually, the Linux kernel will open the file in [RCU](https://www.kernel.org/doc/Documentation/RCU/whatisRCU.txt) mode. This is the most efficient way to open a file. If this try will be failed, the kernel enters the normal mode. The third call is relatively rare, only in the [nfs](https://en.wikipedia.org/wiki/Network_File_System) file system is likely to be used. The `path_openat` function executes `path lookup` or in other words it tries to find a `dentry` (what the Linux kernel uses to keep track of the hierarchy of files in directories) corresponding to a path.

The `path_openat` function starts from the call of the `get_empty_flip()` function that allocates a new `file` structure with some additional checks like do we exceed amount of opened files in the system or not and etc. After we have got allocated new `file` structure we call the `do_tmpfile` or `do_o_path` functions in a case if we have passed `O_TMPFILE | O_CREATE` or `O_PATH` flags during call of the `open` system call. These both cases are quite specific, so let's consider quite usual case when we want to open already existed file and want to read/write from/to it.

In this case the `path_init` function will be called. This function performs some preporatory work before actual path lookup. This includes search of start position of path traversal and its metadata like `inode` of the path, `dentry inode` and etc. This can be `root` directory - `/` or current directory as in our case, because we use `AT_CWD` as starting point (see call of the `do_sys_open` at the beginning of the post).

The next step after the `path_init` is the [loop](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/namei.c#L3457) which executes the `link_path_walk` and `do_last`. The first function executes name resolution or in other words this function starts process of walking along a given path. It handles everything step by step except the last component of a file path. This handling includes checking of a permissions and getting a file component. As a file component is gotten, it is passed to `walk_component` that updates current directory entry from the `dcache` or asks underlying filesystem. This repeats before all path's components will not be handled in such way. After the `link_path_walk` will be executed, the `do_last` function will populate a `file` structure based on the result of the `link_path_walk`. As we reached last component of the given file path the `vfs_open` function from the `do_last` will be called.

This function is defined in the [fs/open.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/open.c) linux kernel source code file and the main goal of this function is to call an `open` operation of underlying filesystem.

That's all for now. We didn't consider **full** implementation of the `open` system call. We skip some parts like handling case when we want to open a file from other filesystem with different mount point, resolving symlinks and etc., but it should be not so hard to follow this stuff. This stuff does not included in **generic** implementation of open system call and depends on underlying filesystem. If you are interested in, you may lookup the `file_operations.open` callback function for a certain [filesystem](https://github.com/torvalds/linux/tree/master/fs).

Conclusion
--------------------------------------------------------------------------------

This is the end of the fifth part of the implementation of different system calls in the Linux kernel. If you have questions or suggestions, ping me on twitter [0xAX](https://twitter.com/0xAX), drop me an [email](anotherworldofworld@gmail.com), or just create an [issue](https://github.com/0xAX/linux-internals/issues/new). In the next part, we will continue to dive into system calls in the Linux kernel and see the implementation of the [read](http://man7.org/linux/man-pages/man2/read.2.html) system call.

**Please note that English is not my first language and I am really sorry for any inconvenience. If you find any mistakes please send me PR to [linux-insides](https://github.com/0xAX/linux-internals).**

Links
--------------------------------------------------------------------------------

* [system call](https://en.wikipedia.org/wiki/System_call)
* [open](http://man7.org/linux/man-pages/man2/open.2.html)
* [file descriptor](https://en.wikipedia.org/wiki/File_descriptor)
* [proc](https://en.wikipedia.org/wiki/Procfs)
* [GNU C Library Reference Manual](https://www.gnu.org/software/libc/manual/html_mono/libc.html#File-Position-Primitive)
* [IA-64](https://en.wikipedia.org/wiki/IA-64) 
* [x86_64](https://en.wikipedia.org/wiki/X86-64)
* [opendir](http://man7.org/linux/man-pages/man3/opendir.3.html)
* [fanotify](http://man7.org/linux/man-pages/man7/fanotify.7.html)
* [fork](https://en.wikipedia.org/wiki/Fork_\(system_call\))
* [execve](https://en.wikipedia.org/wiki/Exec_\(system_call\))
* [symlink](https://en.wikipedia.org/wiki/Symbolic_link)
* [audit](https://linux.die.net/man/8/auditd)
* [inode](https://en.wikipedia.org/wiki/Inode)
* [RCU](https://www.kernel.org/doc/Documentation/RCU/whatisRCU.txt)
* [read](http://man7.org/linux/man-pages/man2/read.2.html)
* [previous part](https://0xax.gitbooks.io/linux-insides/content/SysCall/linux-syscall-4.html)
