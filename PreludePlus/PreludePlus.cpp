// PreludePlus.cpp : Defines the entry point for the application.
//
#undef UNICODE
#define UNICODE
#include <windows.h>
#include <Shlwapi.h>
#include <memory>

#include "PreludePlus.h"
//#include "../dependencies/minhook/include/MinHook.h"

#include <Psapi.h>
#include "../PTD/include/ptd/dll.h"
#include "../dependencies/include/MinHook.h"
#include "util/fixes.h"
#include "../Infrastructure/include/Infrastructure/logging.h"
#include <engine.h>

using namespace std;

int PreludeMain(HINSTANCE hInstance);
#include "dinput.h"

class TestFix : public TempleFix {

	static gfx::Gfx* GetGfx() {
		Engine* self;
		__asm {
			mov self, ecx;
		};
		return &self->graphics;
	}

	void apply() override
	{

		replaceFunction<gfx::Gfx*()>(0x0040D060, GetGfx);
	};
} mainHooks;


int main()
{
	auto& dll = ptd::Dll::GetInstance();
	dll.ReserveMemoryRange(); // reserve space for the game dll as early as possible to avoid rebasing (todo: probably not necessary anymore)

	HINSTANCE hInstance = GetModuleHandleA(0);
	
	auto logFile = /*GetUserDataFolder() +*/ L"PreludePlus.log";
	InitLogging(logFile, (spdlog::level::level_enum::debug)/*config.logLevel*/);

	std::wstring installationDir = L"D:\\Games\\PtD\\";
	dll.Load(installationDir);

	dll.SetDebugOutputCallback([](const std::string& msg) {
		logger->info("{}", msg);
	});

	TempleFixes::apply();

	MH_EnableHook(MH_ALL_HOOKS);

	{
		Engine engine;
		auto ptdStart = ptd::GetRef<void(__cdecl)()>(0x5301F0);
		ptdStart();
	}
	
	return 0;
}


int PreludeMain(HINSTANCE hInstance) {
	return 0;
}