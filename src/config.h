/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/


//TWEAKS
#ifndef CONFIG_H_
#define CONFIG_H_
#define NO_EXPORT_SYM           //Comment if you want api symbols to be exported
#endif

#ifdef NO_EXPORT_SYM
    #define VISIBILITY_FLAG "hidden"
#else
    #define VISIBILITY_FLAG "default"
#endif
