# Usage
Download pre-compiled exe and skeet.dll, put it next to each other, run exe
**If your CPU does not support AVX2+, download the skeet-SSE.dll and rename it to skeet.dll**

You **must** download the libs (gamesense.zip) - and extract the folder into the root folder of your game.

# Crashes
- Make sure that you have the libs correctly placed in your folder, the lib luas should be in, e.g. `E:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive\gamesense`
- Make sure your game has properly started with `-insecure`, and that it is full-screen windowed
- Make sure the injector is running as Administrator
- Make sure you have no anti-viruses running (Obvious..)
- Do not use the skin changer, it is a gamble crash-wise

  ^ If you're crashing on config load do the following:
  1. Inject Skeet
  2. Do NOT load the config
  3. Go into a bot match
  4. Buy every weapon you have a skin on and drop it (pro tip: `sv_cheats 1; mp_maxmoney 65535; impulse 101`)
  5. Load your config
  6. Pick up the weapons off the ground
  7. Turn off their skins
  8. Save config.

# Compilation
This was compiled using mingw msys32 using the following command:
` g++ -m32 -static -static-libgcc -static-libstdc++ -o skeet.exe skeet.cpp`

Any issues open I'll resolve ig
