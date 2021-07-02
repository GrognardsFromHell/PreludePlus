#include "dinput.h"

struct InputSys {
	void* dinput;
	IDirectInputDevice7A* mouse;
	DIMOUSESTATE mouseState;
	BOOL lmbDown;
	BOOL lmbUp;
	BOOL rmbDown;
	BOOL rmbUp;
	RECT cursorRect;
	int mouseSensitivity;
	IDirectInputDevice7A* keyboard;
	BYTE kbState[256];
	BYTE kbStateNew[256];
	HANDLE mouseEventHandler;
	HANDLE kbEventHandler;
};
