# ClassInformer for IDA 7.0

Originally by sirmabus, backported to IDA 7.0. For IDA 7.1, the orignal author has released an [official build](https://sourceforge.net/projects/classinformer/). Unforunately for those of us who are too broke to afford it we need 7.0 :P

Compiled binaries over at the [Releases](../../releases). **If it crashes, use the Debug build and provide a crashdump and crash log! Otherwise I can't fix the issue**

# How to compile it

The process for compiling classinformer can be involved. To streamline the dependency collection process three macros are in place:
1. $(IDADIR)
2. $(QTDIR)
3. $(IDASUPPORT)

To set the paths, go to the Property Manager tab in Solution Explorer, and edit PropertySheet.
It's not important which configuration you edit PropertySheet in, they all use the same file.
Then go to Common Properties -> User Macros and set up macros to paths like below:

### $(IDADIR)
This should be your IDA root directory (the directory containing ida.exe).
Put your IDA SDK directory (idasdk70) into this directory.
So your directory structure may look something like:

```
C:\Program Files\IDA 7.0 $(IDADIR)
+--- idasdk70
     +--- include
     +--- lib
+--- ida.exe
+--- ida64.exe
```

### $(QTDIR)
You need a QT SDK installation to pregenerate the gui files.
Your directory structure may look something like:

```
C:\Program FIles\Qt\qt-5.6.0-x64-msvc2015\5.6\msvc2015_64
+--- bin
+--- lib
+--- include
```

### $(IDASUPPORT)
You need some support libraries that sirmabus wrote, ported for IDA 7.
Setup a directory to hold all of these libraries:
```
idasupport
+--- IDA_SegmentSelect (https://github.com/ecx86/IDA7-SegmentSelect)
+--- IDA_OggPlayer (https://github.com/ecx86/IDA7-OggPlayer)
+--- IDA_WaitBoxEx-7.0 (https://github.com/dude719/IDA_WaitBoxEx-7.0)
+--- SupportLib (https://github.com/ecx86/IDA7-SupportLib)
```
Each of these repositories should have the Release .lib precompiled for you.
If they are not, you can compile them using a process similar to the one used to compile this project.

After your paths are setup, you are ready to compile.
Use Release for the ida.exe plugin, and Release64 for the ida64.exe plugin.
