# **PE文件结构**

PE文件结构展示图

![PE拉伸](https://i-blog.csdnimg.cn/blog_migrate/7ad2336258b373f547b7b1f4ea9f0cdf.png)

PE文件结构详细展示图

![f9f27b52a5a2c011fbbd7a198484f423](D:\文档\3個月逆襲計劃\周报\f9f27b52a5a2c011fbbd7a198484f423.jpeg)

PE文件是由许许多多的结构体组成的，程序在运行时就会通过这些结构快速定位到PE文件的各种资源，其结构大致如图所示，从上到下依次是Dos头、Nt头、节表、节区和调试信息(可选)。其中Dos头、Nt头和节表在本文中统称为PE文件头(因为SizeOfHeaders就是这三个头的总大小)、节区则称为节,所以也可以说PE文件是由PE文件头和节组成。
PE文件头保存着整个PE文件的索引信息，可以帮助PE装载器定位资源，而节则保存着整个PE文件的所有资源。正因为如此，所以存在着这样的说法：头是节的描述，节是头的具体化。



以一个PE文件为例

### DOS头（IMAGE_DOS_HEADER)

```
typedef struct _IMAE_DOS_HEADER {       
    WORD e_magic;        相对文件开头的偏移0，也就是文件的前2个字节，固定值0x4D 0x5A (MZ)
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;        相对文件开头的偏移0x3C,保存IMAGE_NT_HEADERS32这个结构体在PE文件中的偏移地址
} IMAGE_DOS-HEADER, *PIMAGE_DOS_HEADER;
```

当我们用16进制编辑器打开一个PE文件时，就会发现所有PE文件的前两个字节都是MZ,用十六进制表示是4D 5A，这两个字母就是Mark Zbikowski的姓名缩写，他是最初的MS-DOS设计者之一。如果把PE文件的这两个字节修改成其他数据，运行该PE文件就会无法正常运行(跳出黑窗口打印Program too big to fit in memory然后闪退，有兴趣的朋友可以尝试下)。这里可以证明当PE文件运行时，首先就会检测这两个字节，如果不是MZ则会退出运行。

![image-20240913162330263](C:\Users\xuyt\AppData\Roaming\Typora\typora-user-images\image-20240913162330263.png)在该结构体中另一个重要成员就是最后一个成员e_lfanew。该成员的大小是LONG类型4个字节。之所以说它重要是因为它保存着IMAGE_NT_HEADERS32这个结构体在PE文件中的偏移地址，PE文件运行时只有通过该成员才能定位到PE签名(也就是IMAGE_NT_HEADERS32结构体的起始位置)。上图框出来的就是该成员的值0x000000E8,IMAGE_NT_HEADERS32结构体从0x100开始

