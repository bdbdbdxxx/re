# smc

识别：
找到形如下图xor的代码
![](vx_images/367873638193364.png)
再在xor完后下断点，调试看他的值
(这里会很卡)0x4d ,0x5a对应mz，也就是exe头
dump出来
![](vx_images/479724410878722.png)
把txt改成exe
再分析dump分析出来的exe文件