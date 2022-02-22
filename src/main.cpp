#include <iostream>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <fstream>

#define LONG_SIZE 8 //LONG型数据的长度8个字节
#define CODE_SIZE 8//注入断点中断指令的长度，也是8个字节
using namespace std;
vector<string> argv;//存储当前命令所有参数
string cmd;//当前命令字符串
struct Breakpoint {
    unsigned long long addr;
    char backup[CODE_SIZE];
    bool breakpoint_mode;
};

//断点结构体，包含有需要插入断点的地址，对断点地址处的指令进行备份，以及用来标记是否有断点存在的变量
void argparse(); //解析参数

void getdata(pid_t child, long addr, char* str, int len);//从子进程指定地址获取指定长度的数据，长度单位为字节

void putdata(pid_t child, long addr, char* str, int len);//将数据插入子进程指定地址处

void printBytes(const char* tip, char* codes, int len);//打印字节

void showMemory(pid_t pid, unsigned long long addr, long offset = 0, int nbytes = 40);//显示指定地址处指定长度的内存内容

int wait_breakpoint(pid_t pid, int status, Breakpoint& bp);//判断断点是否命中

void breakpoint_inject(pid_t pid, Breakpoint& bp);//给子进程注入断点

void get_base_address(pid_t pid, unsigned long long& base_addr);//从当前子进程的虚拟地址范围获取子进程的起始地址

void show_help();//显示帮助信息

int main() {
    pid_t pid;
    string tracee_name;
    unsigned long long base_addr;
    printf("This is a debugger based on ptrace.\n"
           "For help type \"help\" or \"h\"\n");
    printf("Please input the name of program to be traced:\n");
    getline(cin, tracee_name);//获取本目录下被trace的进程
    tracee_name = "./" + tracee_name;//转换成路径
    int status;
    Breakpoint breakpoint = {.breakpoint_mode=false};//默认不进入断点模式
    switch (pid = fork()) {//fork子进程
        //fork子进程失败
        case -1:
            cout << "Failed to create subprocess!\n";
            return 0;
            //处理子进程
        case 0:
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
                cout << "ptrace error in subprocess!\n";
                exit(1);
            }
            if (execl(tracee_name.data(), tracee_name.data())) {
                cout << "execvp error in subprocess!\n";
                exit(2);
            }
            //子进程，没有成功执行
            cout << "invalid input command : \"" << tracee_name << "\"" << endl;
            exit(3);
        default: {
            while (true) {//开始轮询输入的命令
                printf("(PDebugger) >");
                getline(cin, cmd);
                // 如果输入为exit 则结束当前进程
                if (strcmp(cmd.data(), "exit") == 0) {
                    break;
                }
                argparse();//输入参数解析
                //execute_cmd(pid);
                struct user_regs_struct regs{};//存储子进程当前寄存器的值
                int argc = argv.size();
                char** arguments = new char* [argc];//转换参数类型，以便能够喂到exec函数
                for (int i = 0; i < argc; i++) {
                    arguments[i] = (char*) argv[i].data();
                }
                if (strcmp(arguments[0], "exit") == 0) {//退出操作
                    ptrace(PTRACE_KILL, pid, nullptr, nullptr);//杀死子进程，避免出现僵尸进程
                    break;
                } else if (strcmp(arguments[0], "reg") == 0 || strcmp(arguments[0], "r") == 0) {//获取寄存器内容
                    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
                    printf("rax\t%llx\nrbx\t%llx\nrcx\t%llx\nrdx\t%llx\nrsi\t%llx\nrdi\t%llx\nrbp\t%llx\n"
                           "rsp\t%llx\nrip\t%llx\neflags\t%llx\ncs\t%llx\nss\t%llx\nds\t%llx\nes\t%llx\n",
                           regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp,
                           regs.rsp, regs.rip, regs.eflags, regs.cs, regs.ss, regs.ds, regs.es);
                } else if (strcmp(arguments[0], "step") == 0 || strcmp(arguments[0], "s") == 0) {//单步调试
                    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);//发送single step给子进程
                    wait(&status);//等待子进程收到sigtrap信号
                    if (WIFEXITED(status)) {//执行到最后一条指令退出循环，同时父进程也会结束
                        printf("Process finished.\n");
                        break;
                    }
                } else if (strcmp(arguments[0], "continue") == 0 || strcmp(arguments[0], "c") == 0) {//继续执行
                    ptrace(PTRACE_CONT, pid, nullptr, nullptr);//继续执行，一直到子进程发出发出暂停信号
                    wait(&status);//等待子进程停止，并获取子进程状态值
                    if (!breakpoint.breakpoint_mode) {//没有断点，一直执行到子进程结束
                        if (WIFEXITED(status)) {
                            printf("Process finished.\n");
                            exit(0);
                        }
                    } else {//断点模式被激活，breakpoint_mode字段被置为true
                        wait_breakpoint(pid, status, breakpoint);//等待并判断断点是否被命中
                    }
                } else if (strcmp(arguments[0], "memory") == 0 || strcmp(arguments[0], "m") == 0) {//获取子进程制定区域的内存内容
                    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
                    struct Params {//默认地址采用rip指针的内容，偏移默认为0，默认读取40个字节
                        unsigned long long addr;
                        long offset;
                        int nbytes;
                    } params = {regs.rip, 0, 40};
                    if (argc == 1) {
                        showMemory(pid, regs.rip);//显示内存内容
                    } else {
                        for (int i = 1; i < argc; i++) {//检查是否有额外参数指定
                            if (strcmp(arguments[i], "-addr") == 0) {//指定内存的起始地址
                                params.addr = strtol(arguments[++i], nullptr, 16);
                                continue;//当前参数指定功能，下一个参数指定具体的值，两项获取之后直接跳一步检查别的参数
                            }
                            if (strcmp(arguments[i], "-off") == 0) {
                                params.offset = strtol(arguments[++i], nullptr, 10);
                                continue;
                            }
                            if (strcmp(arguments[i], "-nb") == 0) {
                                params.nbytes = strtol(arguments[++i], nullptr, 10);
                                continue;
                            }
                        }
                        showMemory(pid, params.addr, params.offset, params.nbytes);
                    }
                } else if (strcmp(arguments[0], "ic") == 0) {//计算执行完毕所需指令数
                    long count = 0;
//                    struct user_regs_struct temp_regs{};//存储子进程当前寄存器的值
                    while (true) {
                        wait(&status);//当前子进程还是暂停状态，父进程被阻塞
                        if (WIFEXITED(status)) {
                            printf("\ntotal instruction count is %ld\n", count);
                            exit(0);//指令执行完子进程也结束运行了，父进程退出
                        }
                        ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);//单步执行下一条指令
//                        ptrace(PTRACE_GETREGS, pid, nullptr, &temp_regs);
//                        printf("RIP:%llx\t", temp_regs.rip);
                        count++;
                    }
                } else if (strcmp(arguments[0], "break") == 0 || strcmp(arguments[0], "b") == 0) {
                    if (argc == 2) {//打断点
                        get_base_address(pid, base_addr);//获取子进程的起始虚拟地址
                        //输入的地址实际上是利用objdump反汇编得到的偏移地址，相加得到在虚拟内存中的实际地址
                        breakpoint.addr = strtol(arguments[1], nullptr, 16) + base_addr;
                        breakpoint_inject(pid, breakpoint);//注入断点
                    } else {
                        printf("Please input the address of breakpoint!\n");
                    }
                } else if (strcmp(arguments[0], "help") == 0 || strcmp(arguments[0], "h") == 0) {
                    show_help();//显示帮助信息
                } else {
                    cout << "Invalid Argument!\n";
                }
                argv.clear();//下一轮参数输入之前需要把当前存储的命令清除
            }
            wait(&status);//等待子进程结束之后父进程再退出
        }
    }
}

void argparse() {//解析输入参数
    string param;
    for (char i:cmd + " ") {//因为要用到空格进行分割，为了防止最后一个参数分割不到加一个空格
        if (i != ' ') {
            param += i;
        } else {
            argv.push_back(param);
            param = "";
            continue;
        }
    }
}

/* *
 * 从子进程指定地址读取数据
 * child: 子进程pid号
 * addr: 地址
 * str: 用来存储读取的字节
 * len: 读取字节长度
 * */
void getdata(pid_t child, unsigned long long addr, char* str, int len) {
    char* laddr = str;
    int i = 0, j = len / LONG_SIZE;//计算一共需要读取多少个字
    union u {
        long val;
        char chars[LONG_SIZE];
    } word{};
    while (i < j) {//每次读取1个字，8个字节，每次地址加8(LONG_SIZE)
        word.val = ptrace(PTRACE_PEEKDATA, child, addr + i * LONG_SIZE, nullptr);
        if (word.val == -1)
            perror("trace error");
        memcpy(laddr, word.chars, LONG_SIZE);//将这8个字节拷贝进数组
        ++i;
        laddr += LONG_SIZE;
    }
    j = len % LONG_SIZE;//不足一个字的虚读一个字
    if (j != 0) {
        word.val = ptrace(PTRACE_PEEKDATA, child, addr + i * LONG_SIZE, nullptr);
        if (word.val == -1)
            perror("trace error");
    }
    str[len] = '\0';
}

/* *
 * 从子进程指定地址插入数据
 * child: 子进程pid号
 * addr: 地址
 * str: 用来插入的字节
 * len: 插入字节数
 * */
void putdata(pid_t child, unsigned long long addr, char* str, int len) {
    char* laddr = str;//与getdata类似
    int i = 0, j = len / LONG_SIZE;
    union u {
        long val;
        char chars[LONG_SIZE];
    } word{};
    while (i < j) {
        memcpy(word.chars, laddr, LONG_SIZE);
        if (ptrace(PTRACE_POKEDATA, child, addr + i * LONG_SIZE, word.val) == -1)
            perror("trace error");
        ++i;
        laddr += LONG_SIZE;
    }
    j = len % LONG_SIZE;
    if (j != 0) {
        word.val = 0;
        memcpy(word.chars, laddr, j);
        if (ptrace(PTRACE_POKEDATA, child, addr + i * LONG_SIZE, word.val) == -1)
            perror("trace error");
    }
}

/* *
 * 按字节打印数据
 * tip: 可以附带 字符串输出
 * codes: 需要打印的字节
 * len: 需要打印的字节数
 * */
void printBytes(const char* tip, char* codes, int len) {
    int i;
    printf("%s", tip);
    for (i = 0; i < len; ++i) {
        printf("%02x ", (unsigned char) codes[i]);
        if ((i + 1) % 8 == 0)
            printf("\n");
    }
    puts("");
}

/* *
 * 显示任意内存内容
 * pid: 子进程pid
 * addr: 指定内存基地址
 * offset: 指定相对于基地址的偏移地址
 * nbytes: 需要显示的字节数
 * */
void showMemory(pid_t pid, unsigned long long addr, long offset, int nbytes) {
    printf("current base address is : 0x%llx\n"//显示任意内存内容
           "offset is : %ld\n", addr, offset);
    auto* memory_content = new char[nbytes];
    getdata(pid, addr + offset, memory_content, nbytes);//从指定的地址按照指定的偏移量读取指定的字节数
    printf("The %d bytes after start address: 0x%llx :\n", nbytes, addr + offset);
    printBytes("", memory_content, nbytes);
}

/* *
 * 注入断点
 * pid: 子进程pid
 * bp: 断点结构体
 * */
void breakpoint_inject(pid_t pid, Breakpoint& bp) {
    char code[LONG_SIZE] = {static_cast<char>(0xcc)};//int3中断指令
    //copy instructions into backup variable
    getdata(pid, bp.addr, bp.backup, CODE_SIZE);//先把需要打断点的地址上指令取出备份
    printBytes("get tracee instruction: ", bp.backup, LONG_SIZE);
    puts("try to set breakpoint");
    printBytes("set breakpoint instruction: ", code, LONG_SIZE);
    putdata(pid, bp.addr, code, CODE_SIZE);//将中断指令int3注入
    bp.breakpoint_mode = true;//将断点模式标识变量置为true
}

/* *
 * 等待断点，判断是否命中
 * pid: 子进程pid
 * status: 由外部传入，获取当前tracee停止的状态码
 * bp: 断点结构体
 * */
int wait_breakpoint(pid_t pid, int status, Breakpoint& bp) {
    struct user_regs_struct regs{};
    /* 捕获信号之后判断信号类型	*/
    if (WIFEXITED(status)) {
        /* 如果是EXit信号 */
        printf("\nsubprocess EXITED!\n");
        exit(0);
    }
    if (WIFSTOPPED(status)) {
        /* 如果是STOP信号 */
        if (WSTOPSIG(status) == SIGTRAP) {                //如果是触发了SIGTRAP,说明碰到了断点
            ptrace(PTRACE_GETREGS, pid, 0, &regs);    //读取此时用户态寄存器的值，准备为回退做准备
            /* 将此时的指针与我的addr做对比，如果满足关系，说明断点命中 */
            if (bp.addr != (regs.rip - 1)) {
                /*未命中*/
                printf("Miss, fail to hit, rip:0x%llx\n", regs.rip);
                return -1;
            } else {
                /*如果命中*/
                printf("Hit Breakpoint at: 0x%llx\n", bp.addr);
                /*把INT 3 patch 回本来正常的指令*/
                putdata(pid, bp.addr, bp.backup, CODE_SIZE);
                ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
                /*执行流回退，重新执行正确的指令*/
                regs.rip = bp.addr;//addr与rip不相等，恢复时以addr为准
                ptrace(PTRACE_SETREGS, pid, 0, &regs);
                bp.breakpoint_mode = false;//命中断点之后取消断点状态
                return 1;
            }
        }
    }
    return 0;
}

/* *
 * 获取子进程再虚拟地址空间的起始地址
 * pid: 子进程pid
 * base_addr: 用来存储起始地址
 * */
void get_base_address(pid_t pid, unsigned long long& base_addr) {
    /* *
     * Linux将每一个进程的内存分布暴露出来，以供读取
     * 每个进程的内存分布文件放在/proc/进程pid/maps文件夹里
     * 通过获取pid来读取对应的maps文件
     * */
    string memory_path = "/proc/" + to_string(pid) + "/maps";
    ifstream inf(memory_path.data());//建立输入流
    if (!inf) {
        cerr << "read failed!\n";
        return;
    }
    string line;
    getline(inf, line);//读第一行，根据文件的特点，起始地址之后是"-"字符
    base_addr = strtol(line.data(), nullptr, 16);//默认读到"-"字符为止，16进制
    cout << "get base_addr:0x" << hex << base_addr << endl;
}

void show_help() {
    printf("Type \"exit\" to exit debugger.\n");
    printf("Type \"reg\" or \"r\" to show registers.\n");
    printf("Type \"step\" or \"s\" to single step.\n");
    printf("Type \"continue\" or \"c\" to continue until tracee stop.\n");
    printf("Type \"memory\" or \"m\" to show memory content.\n"
           "\tYou can use \"-addr\" or \"-off\" or \"-nb\" as argument.\n"
           "\tuse \"-addr\" to specify hexadecimal start address of the memory\n"
           "\t\tfor example: Type \"m -addr ff\" to specify the start address 0xff\n"
           "\t\t(default start address is RIP)\n"
           "\tuse \"-off\" to specify the decimal offset from the start address\n"
           "\t\t(default offset is 0)\n"
           "\tuse \"-nb\" to specify the decimal number of bytes to be displayed\n"
           "\t\t(default number is 40)\n");
    printf("Type \"ic\" to count total instructions.\n");
    printf("Type \"break\" or \"b\" to insert breakpoint.\n"
           "\tfor example: Type \"b 555555555131\" to specify the breakpoint address 0x555555555131\n");
}






