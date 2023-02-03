# SM4-SIMD

复现并优化博客https://www.cnblogs.com/kentle/p/15562530.html。

### 主要原理

AVX2指令优化SM4。

8组并行计算方式，优化SM4性能。

配合查表优化。

查表生成中有所有表生成脚本。

### 优化点

密钥生成用查表法+AVX并行。

### 测试结果

x64 开启O2

![image](https://github.com/0CarryT0/SM4-SIMD/blob/master/test.png)

