# Usage
Download pre-compiled exe and skeet.dll, put it next to each other, run exe
**If your CPU does not support AVX2+, download the skeet-SSE.dll and rename it to skeet.dll**

# Compilation
This was compiled using mingw msys32 using the following command:
` g++ -m32 -static -static-libgcc -static-libstdc++ -o skeet.exe skeet.cpp`

Any issues open I'll resolve ig
