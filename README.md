# ptraceDebugger
利用ptrace系统调用实现的debugger

test文件夹存放一些测试用例作为tracee以及linux地址随机化关闭脚本

具体说明可以前往我的博客：
http://kakaluoto.xyz/2022/02/22/%E5%9F%BA%E4%BA%8Eptrace%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8%E5%AE%9E%E7%8E%B0%E4%B8%80%E4%B8%AAdebugger/

Notice:这个小demo是课程作业，故而只满足基本的作业要求，有很多地方不是很严谨。。。。。。

# 基于ptrace的debugger设计
## 1. 程序的设计思路
### 1.1 设计思路

本次设计实现的debugger针对被调试进程主要实现了6项功能:
+ 可以读取被调试进程CPU所有寄存器的值
+ 可以对被调试进程进行单步调试
+ 可以恢复被调试进程运行
+ 可以查看被调试进程任意内存空间
+ 可以计算被调试进程执行完需要多少条指令
+ 可以在指定地址插入断点

为了在不同的功能之间进行切换，使用循环轮询手动输入参数的方式来决定使用哪一项功能。

```c++
Type "exit" to exit debugger.
Type "reg" or "r" to show registers.
Type "step" or "s" to single step.
Type "continue" or "c" to continue until tracee stop.
Type "memory" or "m" to show memory content.
	You can use "-addr" or "-off" or "-nb" as argument.
	use "-addr" to specify hexadecimal start address of the memory
		for example: Type "m -addr ff" to specify the start address 0xff
		(default start address is RIP)
	use "-off" to specify the decimal offset from the start address
		(default offset is 0)
	use "-nb" to specify the decimal number of bytes to be displayed
		(default number is 40)
Type "ic" to count total instructions.
Type "break" or "b" to insert breakpoint.
	for example: Type "b 555555555131" to specify the breakpoint address 0x555555555131
```

系统调用Ptrace的定义：

```c++
long ptrace(enum __ptrace_request request, pid_t pid,void *addr,void *data);
```

ptrace的第一个参数可以通过指定request请求来实现不同的功能。使用PTRACE_GETREGS参数来一次性获取所有寄存器的值，使用PTRACE_SINGLESTEP来进行单步调试，PTRACE_CONT来让被暂停的进程恢复运行。

为了读取任意内存空间，需要知道内存空间的起始地址，一次性读取多少个字节，因此默认采用rip寄存器存放的指针作为默认的起始地址，也就是默认从下一条指令的地址开始读，可以指定一次性读多少个字节，这里我默认一次性读取40个字节，为了既能够读到rip指针之后的数据也能读到rip指针之前的数据，引入偏移量offset，这样可以在指定了起始地址的基础上加上偏移量，从而理论上能够读取任意内存区域。当然，如果明确知道要读的内存起始地址，也可以忽略rip指针直接指定起始地址。

计算进程执行完需要多少条指令比较简单，只需要不停单步执行直到退出，每执行一步就计数即可。

给进程打断点的实现最为困难，本次设计仅针对进程特定地址进行插入断点。可以使用Ptrace的PTRACE_PEEKDATA，PTRACE_POKEDATA两个请求，来在进程指定的地址读出指令和注入新的指令。因此可以在指定的地址插入int3(0xcc)中断指令实现断点，为了让插入断点的进程依然能够恢复运行，在插入断点之前对该地址原有指令进行备份，遇到断点之后再将备份的指令还原，并且恢复命中断点时的寄存器值，尤其是rip指针需要减1，回退一个地址。

![](https://www.helloimg.com/images/2022/02/22/Gra7LC.png)

过程如上图所示，第一步rip先指向byte2对应地址处，利用PTRACE_PEEKDATA将byte2,byte3取出备份，同时保存当前寄存器值，为恢复做备份。第二步插入0xcc,0x00指令，即int3中断指令，执行一步来到第三步rip指向0x00，触发中断，子进程暂停。第四步，为了让子进程继续运行，将备份的原始指令写入rip-1处，并且利用PTRACE_SETREGS将寄存器值恢复成原来的值，此时rip跟着上移。这样子进程可以继续正常运行不会core dump。以上四步构成了在byte2对应地址处打上断点的操作。

要完成插入断点并且运行到断点停止，并且能恢复原有指令继续正常运行的非常关键的一点就是需要知道子进程是否命中断点。因为子进程完全有可能因为接收到其他信号而暂停，同时产生SIGTRAP信号发送给父进程，并不一定就是因为断点而暂停并发送SIGTRAP信号。因此在等待被调试进程的时候，当截获SIGTRAP信号需要取出rip指针，此时如果是断点触发的暂停信号，rip肯定指向0xcc指令的下一条指令，故而只需要判断当初我们输入的打断点的地址addr是否等于rip-1。如果相等那么断点命中，命中之后就可以将原有指令恢复，把寄存器值恢复。

## 2. 程序的模块划分

主要函数

```Cpp
void getdata(pid_t child, long addr, char* str, int len);
/* *
 * 从子进程指定地址插入数据
 * child: 子进程pid号
 * addr: 地址
 * str: 用来插入的字节
 * len: 插入字节数
 * */

void putdata(pid_t child, long addr, char* str, int len);
/* *
 * 按字节打印数据
 * tip: 可以附带 字符串输出
 * codes: 需要打印的字节
 * len: 需要打印的字节数
 * */

void showMemory(pid_t pid, 
                unsigned long long addr, long offset = 0, int nbytes = 40);
/* *
 * 显示任意内存内容
 * pid: 子进程pid
 * addr: 指定内存基地址
 * offset: 指定相对于基地址的偏移地址
 * nbytes: 需要显示的字节数
 * */

int wait_breakpoint(pid_t pid, int status, Breakpoint& bp);
/* *
 * 注入断点
 * pid: 子进程pid
 * bp: 断点结构体
 struct Breakpoint {
    unsigned long long addr;
    char backup[CODE_SIZE];
    bool breakpoint_mode;
};
//断点结构体，需要插入断点的地址addr
//断点地址处的指令的备份backup
//用来标记是否有断点存在的变量breakpoint_mode
 * */

void breakpoint_inject(pid_t pid, Breakpoint& bp);
/* *
 * 等待断点，判断是否命中
 * pid: 子进程pid
 * status: 由外部传入，获取当前tracee停止的状态码
 * bp: 断点结构体
 * */

void get_base_address(pid_t pid, unsigned long long& base_addr);
/* *
 * 获取子进程再虚拟地址空间的起始地址
 * pid: 子进程pid
 * base_addr: 用来存储起始地址
 * */

void show_help();
//显示帮助信息
```


## 3. 程序使用说明及运行结果

当前目录下含有5个文件

```shell
/ptrace_debugger$ tree
.
├── ASLR.sh
├── main.cpp
├── ptrace_debugger
├── test
└── test.cpp

0 directories, 5 files

```

Linux 平台上 ASLR 分为 0，1，2 三级，用户可以通过一个内核参数 randomize_va_space 进行等级控制。它们对应的效果如下：

0：没有随机化。即关闭 ASLR。
1：保留的随机化。共享库、栈、mmap() 以及 VDSO 将被随机化。
2：完全的随机化。在 1 的基础上，通过 brk() 分配的内存空间也将被随机化。

ASLR.sh脚本用来设置随机化等级：

ptrace_debugger是main.cpp编译的可执行文件

test是被调试进程test.cpp编译的可执行文件

执行如下命令关闭随机化：

```shell
/ptrace_debugger$ ./ASLR.sh 0
change ASLR level to:
0
```

运行ptrace_debugger：

```shell
/ptrace_debugger$ ./ptrace_debugger 
This is a debugger based on ptrace.
For help type "help" or "h"
Please input the name of program to be traced:
test
(PDebugger) >
```

查看寄存器：

```shell
(PDebugger) >r 
rax	0
rbx	0
rcx	0
rdx	0
rsi	0
rdi	0
rbp	0
rsp	7fffffffdf50
rip	7ffff7fd0100
eflags	200
cs	33
ss	2b
ds	0
es	0
(PDebugger) >
```

单步调试：

```shell
(PDebugger) >r
rax	0
rbx	0
rcx	0
rdx	0
rsi	0
rdi	0
rbp	0
rsp	7fffffffdf50
rip	7ffff7fd0100
eflags	200
cs	33
ss	2b
ds	0
es	0
(PDebugger) >s
(PDebugger) >r
rax	0
rbx	0
rcx	0
rdx	0
rsi	0
rdi	7fffffffdf50
rbp	0
rsp	7fffffffdf50
rip	7ffff7fd0103
eflags	202
cs	33
ss	2b
ds	0
es	0
(PDebugger) >
```

恢复运行：

```shell
(PDebugger) >s
(PDebugger) >r
rax	0
rbx	0
rcx	0
rdx	0
rsi	0
rdi	7fffffffdf50
rbp	0
rsp	7fffffffdf48
rip	7ffff7fd0df0
eflags	202
cs	33
ss	2b
ds	0
es	0
(PDebugger) >c
Process finished.
```

查看任意内存空间：

```shell
(PDebugger) >m -off -20 -nb 40
current base address is : 0x7ffff7fd0df0
offset is : -20
The 40 bytes after start address: 0x7ffff7fd0ddc :
00 00 00 00 bf 01 00 00 
00 5b e9 95 d4 01 00 0f 
1f 44 00 00 f3 0f 1e fa 
55 48 89 e5 41 57 49 89 
ff 41 56 41 55 41 54 53 

(PDebugger) >
```

计算指令数：

```shell
(PDebugger) >ic

total instruction count is 117802

```

断点调试：

先进行反汇编

```shell
hy@ubuntu:~/下载/ptrace_debugger$ ls
ASLR.sh  main.cpp  ptrace_debugger  test  test.cpp
hy@ubuntu:~/下载/ptrace_debugger$ objdump -d test

test：     文件格式 elf64-x86-64

   
......省略......


0000000000001129 <main>:
    1129:	f3 0f 1e fa          	endbr64 
    112d:	55                   	push   %rbp
    112e:	48 89 e5             	mov    %rsp,%rbp
    1131:	c7 45 f4 04 00 00 00 	movl   $0x4,-0xc(%rbp)
    1138:	c7 45 f8 08 00 00 00 	movl   $0x8,-0x8(%rbp)
    113f:	8b 55 f4             	mov    -0xc(%rbp),%edx
    1142:	8b 45 f8             	mov    -0x8(%rbp),%eax
    1145:	01 d0                	add    %edx,%eax
    1147:	89 45 fc             	mov    %eax,-0x4(%rbp)
    114a:	b8 00 00 00 00       	mov    $0x0,%eax
    114f:	5d                   	pop    %rbp
    1150:	c3                   	retq   
    1151:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    1158:	00 00 00 
    115b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

......省略......
 

Disassembly of section .fini:

00000000000011d8 <_fini>:
    11d8:	f3 0f 1e fa          	endbr64 
    11dc:	48 83 ec 08          	sub    $0x8,%rsp
    11e0:	48 83 c4 08          	add    $0x8,%rsp
    11e4:	c3                   	retq  
```

可以看到main函数入口地址是0x1129

打断点：

```shell
Please input the name of program to be traced:
test
(PDebugger) >b 1129
get base_addr:0x555555554000
get tracee instruction: f3 0f 1e fa 55 48 89 e5 

try to set breakpoint
set breakpoint instruction: cc 00 00 00 00 00 00 00 

(PDebugger) >c
Hit Breakpoint at: 0x555555555129
(PDebugger) >r
rax	555555555129
rbx	555555555160
rcx	555555555160
rdx	7fffffffdf68
rsi	7fffffffdf58
rdi	1
rbp	0
rsp	7fffffffde68
rip	555555555129
eflags	246
cs	33
ss	2b
ds	0
es	0
(PDebugger) >s
(PDebugger) >c
Process finished.
```

## 5. 相关脚本


### 5.1 被调试子进程tracee

test.cpp:

```cpp
int main() {
    int i = 4;
    int j = 8;
    int k = i + j;
    return 0;
}
```

### 5.2 关闭ASLR脚本

```shell
#!/bin/bash

if [ $# == 0 ]		# $# means the number of parameters
then
    echo 'current ASLR level:'
    cat /proc/sys/kernel/randomize_va_space
    echo 'use option "-h" for help.'
elif [ $# == 1 ]
then
    if [ $1 == 0 ]
    then 
        sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"
        echo "change ASLR level to:"
        cat /proc/sys/kernel/randomize_va_space
    elif [ $1 == 1 ]
    then
        sudo bash -c "echo 1 > /proc/sys/kernel/randomize_va_space"
        echo "change ASLR level to:"
        cat /proc/sys/kernel/randomize_va_space
    elif [ $1 == 2 ]
    then
        sudo bash -c "echo 2 > /proc/sys/kernel/randomize_va_space"
        echo "change ASLR level to:"
        cat /proc/sys/kernel/randomize_va_space
    elif [ $1 == "-h" ]
    then
        echo ""
        echo "### bash ./ASLR"
        echo "-->   show current ASLR level."
        echo ""
        echo "### bash ./ASLR -h"
        echo "-->   show help info."
        echo ""
        echo "### bash ./ASLR 0"
        echo "-->   change ASLR level to 0."
        echo ""
        echo "### bash ./ASLR 1"
        echo "-->   change ASLR level to 1."
        echo ""
        echo "### bash ./ASLR 2"
        echo "-->   change ASLR level to 2."
        echo ""
    else
        echo "syntax error!"
        echo 'use option "-h" for help.'
    fi
else
    echo "syntax error!"
    echo 'use option "-h" for help.'
fi
```
