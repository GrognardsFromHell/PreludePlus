#include "sound_engine.h"
#include "ptd/dll.h"

struct SoundFx {
	int BASS_sample;
	char fname[48];
};

struct MusicSegment {
	int segLength;
	int data[15];
};

struct MusicTrack {
	int numFiles;
	MusicSegment* segments;
	int patternLen;
	char name[32];
	int field_1028;
};


ptd::validate_size<SoundSystem, 0x34> soundSize;