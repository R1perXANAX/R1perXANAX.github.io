---
layout: post
title: Usermode Anticheat/Anti-dll-injection Bypass
date: 2022-11-09
categories: ["tutorials", "reverse engineering"]
---


**PREREQUISITES:** Basic reverse engineering skills.


#### Intro

The softwere we are going to analyze today is a usermode anticheat that should prevent any kind of dll-injection. This challenge was made by a guy on [Guided Hacking forum](https://guidedhacking.com/threads/bypass-me.15270/).

>"Features:
>Obfuscated integrity check, thread check, anti debug and some other stuff."

Let's start

#### Static Analysis
Since it is not heavily obfuscated, we can deduce some stuff from static analysis. I used IDA Pro 7.7 but Ghidra should be good too. From the pseudo code generated we can get a basic idea about how the anticheat works. 

![Half main](https://cdn.discordapp.com/attachments/975802761838985276/1039935354909757461/image.png)

We can see from the half part of main thread that 4 threads are created with CreateThread Api call. 

String are obufscated with simple xor encryption.

Basically the decryption algorithm iterates over all characters of the string and xor them with (index + 67) as you can see from the image below. Sometime it changes but you can easly get from the pseudocode or from the debugger. It's your job.

![string obf](https://cdn.discordapp.com/attachments/975802761838985276/1039936618942971964/image.png)


###### Detection Vectors/Threads

We figured out that 4 threads are created on the initialization of the program. The third argument of CreateThread is a pointer to the function that will be executed. The first call points to StartAddress. Double click and we can see the function flow.

-I didn't spend too much time on that function but from my understanding, is performing an integrity check. I deduced it from the calls to VirtualAlloc, the structure of the for loops and the encrypted strings .When you perform an integrity check, usually you copy some section or the entire pe file into memory in order to compare the actual code with the one in memory later on and check if any changes have been applied. My bypass uses 0 patches on the code so that thread is not important for me. I recommend the analysis of this thread to anyone who wants to learn more about integrity checks

-The second thread is Debug Check, we can see that from the Api calls as: IsDebuggerPresent(), PEB->BeingDebugged. Those are easy to bypass, but we can find a little tricky one in the main thread. 
If we go below the calls to CreateThread we can see a call to AddVectoredExceptionHandler. Usually this is a technique used to detect the presence of a debugger. I leave an article that explain in details this technique: [Anti-Debug: Exceptions](https://anti-debug.checkpoint.com/techniques/exceptions.html).

In a nutshell when the program is executed without debugger the function inside AddVectoredExceptionHandler (the handler, 2nd argument) is executed succesfully, but when we run inside a debugger, the handler is not executed and we get detected.

I haven't done a lot of dynamic analysis to bypass that anticheat, but for what little I needed the debugger I used scyllaHide to save time and avoid to manually bypass that checks. You could try to bypass it manually. For the first 2 checks there are no problems, but for the vectored execption you need to do some research first. 


-The third one has been the most annoying. This thread is checking the page-protection rights. This thread is the only one that can detect a manual map injection. It checks if some sections of the executable have Read-Write-Execute privilege. Anyone who has ever tried to manually map a dll should know that a shellcode needs to be injected to start the dll. The memory that will contain the shellcode will have RWX privilege. How i know that is checking that? If you look into the code you will see a call to VirtualQuery with a if condition that checks if the current page has RWX privilege. Also if you decrypt the error message string, it will display "Detected RWX memory edit". We need to stop that thread execution in order to inject.

-The last thread is checking the module list inside PEB. We can deduce that from the for loop
![third thread](https://cdn.discordapp.com/attachments/975802761838985276/1039944128890413197/image.png)

I think if the modules (dlls) loaded are not the same as the max modules that the program should have, you get detected. Since i will use manual mapping to inject my dll, i dont care about this thread, but if you are going to use LoadLibrary you should delete your dll from the module list after the injection. 
[How to delete dll from the module list](https://guidedhacking.com/threads/ntqueryinformationprocess-how-to-loop-through-peb-ldr-module-list.14789/).


###### Threads integrity check

One nice thing I've learned is a simple thread integrity check.

![t int check](https://cdn.discordapp.com/attachments/975802761838985276/1039948312729616404/image.png)

At first glance it confused me for a moment, but after reading well msdn about SuspendThread, i figured out how all works. SuspendThread returns the number of actual suspended thread and if it fails, it returns -1. Basically it iterates over all 4 thread handles, suspend one by one and resume the thread suspended before suspending the other one. With this flow, SuspendThread should return always 0 cause no thread is suspended while SuspendThread is called, and if an handle is invalid, it returns -1 that is equals to true so it enter the error block inside if condition. So if we interrupt a thread or a handle is invalid due CreateThread was not called, we will be detected.

That's not the only thread integrity check of this anticheat. At the bottom we can see 

![m int check](https://cdn.discordapp.com/attachments/975802761838985276/1039951109806096404/image.png)

Those 2 checks are inside a while loop, that is the main while loop, executed after the initialization of the threads

![m int init]https://cdn.discordapp.com/attachments/975802761838985276/1039951517559570492/image.png

If the time taken to complete a cycle is greater than 3 seconds, we will be detected. That was the last check, interesting....



#### The Bypass

There are multiple ways to achive that, but i was wondering if it was possible to bypass this anticheat without any patches. That's the idea that came in my mind after an intense meditation.

The only thread that detects our manual map is the third one( Page Protection ).

Steps of the loader:

-Suspend all threads
-Manually map the dll
-Resume all threads (less than 3 seconds to do that).

Steps of the dll:

-Terminate Page protection thread
-Change in the array of handles the page protection thread handle that now is invaid with another valid one( basically we spoof an handle ) in order to lets  SuspendThread run correctly.

With this we should be able to bypass all detection vectors. We need to find the offset of the array that contains the handles to spoof. 

![offset](https://cdn.discordapp.com/attachments/975802761838985276/1039953856488034405/image.png)


We can see that the array is equal to a global variable called Src. Now we rebase the whole program to 0 (Edit->Segments->Rebase Program) and double click on Src and we get this address:
".data:00000000000066F8" so the offset from the module base address is -> 0x66F8

We can define a structure or an array for this address, i choosed a structure.

```cpp
struct THREADLIST {
    HANDLE main, debugCheck, pageProtect, moduleCheck;
};
```

An array like that would be good too
```cpp
HANDLE handles[4];
```


Here we have the code of the loader:

```cpp
    std::vector<HANDLE> suspendedThreads;
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        te32.dwSize = sizeof(THREADENTRY32);
        BOOL bRet = Thread32First(hThreadSnap, &te32);
        while (bRet) {
            if (te32.th32OwnerProcessID == PID) {
                HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, NULL, te32.th32ThreadID);
                if (threadHandle != INVALID_HANDLE_VALUE) {
                    if (SuspendThread(threadHandle) == -1) {
                        std::cout << "SuspendThread failed: " << GetLastError() << std::endl;
                    }
                    else {
                        suspendedThreads.push_back(threadHandle);
                    }
                }
            }
            bRet = Thread32Next(hThreadSnap, &te32);
        }
    }
    if (!ManualMap(hProc, szDllFile)) {
        CloseHandle(hProc);
        std::cout << "Manual Map failed!" << std::endl;
        system("Pause");
        return 0;
    }
    Sleep(500); 
    for (auto i : suspendedThreads) {
        if(ResumeThread(i) == -1)
            std::cout << "ResumeThread failed: " << GetLastError() << std::endl;
    }
    CloseHandle(hProc);
```

is a modified version of the [GH manual mapper](https://www.youtube.com/watch?v=qzZTXcBu3cE)



That's the dll code

```cpp
struct THREADLIST {
    HANDLE main, debugCheck, pageProtect, moduleCheck;
};

struct KEYMAP_C {
    int exitKey         = VK_END;
}; KEYMAP_C keyMap;

void AccurateSleep(int milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}
DWORD WINAPI Main(HMODULE hModule) {
    FILE* file;
    AllocConsole();
    freopen_s(&file, "CONOUT$", "w", stdout);

    std::cout << "\nAttempt to bypass\n";
    THREADLIST* TL = *reinterpret_cast<THREADLIST**>(reinterpret_cast<UINT_PTR>(GetModuleHandle(NULL)) + 0x66f8); // get the handle list

    if (TerminateThread(TL->pageProtect, NULL)) {
        TL->pageProtect = TL->debugCheck; // spoof thread handle
        std::cout << "BYPASSED";
    }

    while (!GetAsyncKeyState(keyMap.exitKey)) {
        AccurateSleep(2);
    }

    if (file != NULL)
        fclose(file);
    
    FreeConsole();
    FreeLibraryAndExitThread(hModule, NULL);
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Main, hModule,NULL, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

```


I hope this writeup was useful, Now it's your turn. Greetings, R1perXNX

