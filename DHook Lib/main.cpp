// dhook.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "dhook.h"

int main()
{
    DHOOK_hook(MessageBoxA, NewMessageBoxA);
    MessageBoxA(NULL, "Hello World", "Bye", MB_OK);
    DHOOK_unhook();
    MessageBoxA(NULL, "Hello World", "Bye", MB_OK);

    return 0;
}

/*
#Create a template for hooked function for MessageBoxA
#
*/
