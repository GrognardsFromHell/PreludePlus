#include "sound_engine.h"
#include "input_system.h"
#include "gfx.h"

struct MeshDef;
struct TextureDef;

struct Engine {
	char curDir[256];
	SoundSystem soundSys;
	InputSys inputSys;
	gfx::Gfx graphics;
	int meshCount;
	MeshDef* meshes[768];
	int textureCount;
	TextureDef* textures;
};
