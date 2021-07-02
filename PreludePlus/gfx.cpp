#include <gfx.h>
#include <ptd/dll.h>

ptd::validate_size<gfx::Gfx, 0x844> sizeGfx;

gfx::Gfx* gfx::GfxSystem::Get()
{
	ptd::GetRef<void*>(0x00400000);
	return nullptr;
}

