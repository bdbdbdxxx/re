首先我们要知道

我们的目标是要找到像“flag{xxx},NSSCTF{xxx}"这种东西

那么我们开始吧><



以   运行即得   这个题为例

你直接打开是没有办法打开的（bushi)



第一步

打开ida.

第二步

把文件拖进去

第三部

什么都同意

然后你就会看到这样的画面

![image-20241011193520126](C:\Users\xuyt\AppData\Roaming\Typora\typora-user-images\image-20241011193520126.png)

然后使用最nb的键“F5”，一键转（伪C）代码

![image-20241011193720069](C:\Users\xuyt\AppData\Roaming\Typora\typora-user-images\image-20241011193720069.png)

然后发现什么都没看到（bushi)

这时再用一个万能键“shift+F12"

打开字符串列表

像这样

![image-20241011194000340](C:\Users\xuyt\AppData\Roaming\Typora\typora-user-images\image-20241011194000340.png)

第二个就是我们要的了（>^<)!!!!


```
import idaapi
import ida_bytes

# 获取当前加载文件的基地址和大小
base = idaapi.get_imagebase()
size = idaapi.get_inf_attr(idaapi.INF_MAXEA) - base

# 读取内存中的数据
data = ida_bytes.get_bytes(base, size)

# 指定导出文件的路径
output_file = "path/to/your/output.elf"

# 将数据写入文件
with open(output_file, "wb") as f:
    f.write(data)

print(f"ELF file exported to {output_file}")
```