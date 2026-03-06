python逆向

![image-20241014195931361](C:\Users\xuyt\AppData\Roaming\Typora\typora-user-images\image-20241014195931361.png)

```
 python pyinstxtractor.py D:\文档\ctf\re\p\2024\2024极客\re\奇 怪的RC4\奇怪的RC4\easy_xor_and_rc4.exe           
```
pyinst文件放在这个目录下了，到时候直接复制过去

然后找到

uncompyle6直接反编译
```
uncompyle6 1.pyc > 1.py
```

![image-20240804125420204](C:\Users\xuyt\AppData\Roaming\Typora\typora-user-images\image-20240804125420204.png)

可能有些给的pyc会缺少魔术头，但是一般会告诉你



新生培训PYC

## 1、什么是pyc

pyc是一种二进制文件，是由py文件经过编译后，生成的文件，是一种byte code，py文件变成pyc文件后，加载的速度有所提高。pyc的内容，是跟python的版本相关的，不同版本编译后的pyc文件是不同的，2.5编译的pyc文件，2.4版本的 python是无法执行的。

## 2、为什么要生成pyc文件

1、优点在于.pyc文件的执行速度快于.py文件。

2、开发商业软件时，一定程度上防止源码泄漏出去。所以就需要编译为pyc后，再发布出去。当然，pyc文件也是可以反编译的，不同版本编译后的pyc文件是不同的，需要不同的反编译工具。

## 3、如何生成pyc文件

1、单个生成

```
python -m py_compile /path/to/需要生成.pyc的脚本.py
```

2、批量生成

```
python -m py_compile /path/to/{需要生成.pyc的脚本1,脚本2,...}.py #或者/path/to/
```

3、使用python自带的模块生成

import py_compile

py_compile.compile(r'H:\game\test.py')

\#此处尽可能使用raw字符串，从而避免转义的麻烦。比如，这里不加“r”的话，你就得对斜杠进行转义

compile函数原型：

compile(file[, cfile[, dfile[, doraise]]])

file 表示需要编译的py文件的路径

cfile 表示编译后的pyc文件名称和路径，默认为直接在file文件名后加c 或者 o，o表示优化的字节码

dfile 表示编译出错时，将报错信息中的名字“file”替换为“dfile”

doraise 可以是两个值，True或者False，如果为True，则会引发一个PyCompileError，否则如果编译文件出错，则会有一个错误，默认显示在sys.stderr中，而不会引发异常

(来自python2.5文档)

4、Python自带模块批量生成pyc文件

一般来说，我们的工程都是在一个目录下的，一般不会说仅仅编译一个py文件而已，而是需要把整个文件夹下的py文件都编译为pyc文件，python又为了我们提供了另一个模块：compileall 。使用方法如下：

**compile_dir**函数的说明：

compile_dir(dir[, maxlevels[, ddir[, force[, rx[, quiet]]]]])

dir 表示需要编译的文件夹位置

maxlevels 表示需要递归编译的子目录的层数，默认是10层，即默认会把10层子目录中的py文件编译为pyc

ddir 原文：it is used as the base path from which the filenames used in error messages will be generated。

force 如果为True，则会强制编译为pyc，即使现在的pyc文件是最新的，还会强制编译一次，pyc文件中包含有时间戳，python编译器会根据时间来决定，是否需要重新生成一次pyc文件

rx 表示一个正则表达式，比如可以排除掉不想要的目录，或者只有符合条件的目录才进行编译

quiet 如果为True，则编译后，不会在标准输出中，打印出信息

(来自python2.5文档)

通过上面的方法，可以方便的把py文件编译为pyc文件了，从而可以实现部分的源码隐藏，保证了python做商业化软件时，保证了部分的安全性吧。

## 那么我们如何反编译pyc文件

**使用uncompyle6**

1、使用 pip 安装该反编译包（默认已有 python 环境）：

pip install uncompyle

如果速度很慢或者直接报 HTTP 错误，可以使用国内源（下述为清华源）进行下载安装：

pip install uncompyle -i https://pypi.tuna.tsinghua.edu.cn/simple



2、进入 .pyc 文件所在的文件夹，反编译单个文件：

uncompyle6 test.pyc > test.py

![image-20240804125420204](C:\Users\xuyt\AppData\Roaming\Typora\typora-user-images\image-20240804125420204.png)

好像要求 python 版本 <= 3.9！！！



3、反编译目录中的所有 .pyc 文件：

import glob
import uncompyle6

pycs = glob.glob('./transforms/*.pyc')





有些给的pyc会缺少魔术头，但是一般会告诉你是python几的，可以搜索对应的魔术头补全