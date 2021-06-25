
#include "crash_reporting.h"

#include "infrastructure/breakpad.h"
#include "platform/windows.h"

Breakpad::Breakpad(const std::wstring &crashDumpFolder)
{

	mHandler = std::make_unique<InProcessCrashReporting>(crashDumpFolder, [this](const std::wstring &minidump_path) {

		std::wstring msg = L"Sorry! PreludePlus seems to have crashed.A crash report was written to " + minidump_path + L".\n\n"
			L"If you want to report this issue, please contact us on our forums at RPGCodex or send an email to templeplushelp@gmail.com."
		;
		if (!extraMessage().empty()) {
			msg.append(extraMessage());
		}

		// Now starts the tedious work of reporting on this crash, heh.
		MessageBoxW(NULL, msg.c_str(), L"PreludePlus  Crashed - Oops!", MB_OK);

	});

}

Breakpad::~Breakpad()
{
}
