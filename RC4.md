RC4

```
#include<bits/stdc++.h>
using namespace std;

void rc4_init(unsigned char *s,unsigned char *key, unsigned long Len)
{
    //初始化长度为256的S盒
    int i=0,j=0;
    char k[256]={0};
    unsigned char tmp=0;

    for(i=0;i<256;i++) 
    {
        s[i]=i;//将0到255的互不重复的元素装入S盒
        k[i]=key[i%Len];
    }

    for(i=0;i<256;i++)
    {
        //第二个for循环根据密钥打乱S盒
        //i确保S-box的每个元素都得到处理，j保证S-box的搅乱是随机的
        j=(j+s[i]+k[i])%256;
        tmp=s[i];
        s[i]=s[j];     //交换s[i]和s[j]
        s[j]=tmp;
    }
}

void rc4_crypt(unsigned char *s,unsigned char *Data,unsigned long Len)
{
    int i=0,j=0,t=0;
    unsigned long k=0;
    unsigned char tmp;

    for(k=0;k<Len;k++)//循环中还改变了S盒
    {
        i=(i+1)%256;
        j=(j+s[i])%256;
        tmp=s[i];
        s[i]=s[j];      //交换s[x]和s[y]
        s[j]=tmp;
        t=(s[i]+s[j])%256;
        //^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        //每收到一个字节，就进行while循环。通过一定的算法定位S盒中的一个元素
        Data[k]^=s[t];//并与输入字节异或，得到k
    }
    //如果输入的是明文，输出的就是密文；如果输入的是密文，输出的就是明文
}

int main()
{
    unsigned char s[256] = { 0 }, s2[256] = { 0 };//S-box
    char key[256] = { "NewStar" };
    unsigned char pData[512] = {0XC4,0x60,0x0AF,0xB9,0xE3,0xFF,0x2E,0x9B,0xF5,0x10,0x56,0x51,0x6E,0xee,0x5f,0x7d,0x7d,0x6e,0x2b,0x9c,0x75,0xb5};
    unsigned long len = 22;
    int i;

    printf("pData=%s\n", pData);
    printf("key=%s,length=%d\n\n", key, strlen(key));
    rc4_init(s, (unsigned char*)key, strlen(key)); //已经完成了初始化
    printf("完成对S[i]的初始化，如下：\n\n");
    for (i = 0; i<256; i++)
    {
        printf("%02X,", s[i]);
        if (i && (i + 1) % 16 == 0)putchar('\n');
    }
    printf("\n\n");
    for (i = 0; i<256; i++)           //用s2[i]暂时保留经过初始化的s[i]，很重要的！！！
    {
        s2[i] = s[i];
    }
    printf("已经初始化，现在加密:\n\n");
//    rc4_crypt(s, (unsigned char*)pData, len);//加密
    printf("pData=%s\n\n", pData);
    printf("已经加密，现在解密:\n\n");
    //rc4_init(s,(unsignedchar*)key,strlen(key));//初始化密钥
    rc4_crypt(s2, (unsigned char*)pData, len);//解密
    printf("pData=%s\n\n", pData);
    return 0;
}
```

