struct SoundFx;
struct MusicTrack;

struct SoundSystem {
	SoundFx* sounds;
	MusicTrack* musicTracks;
	int soundEn;
	int musicEn;
	int soundVolume;
	int musicVolume;
	int field_18; // inited to 10, probably another volume
	int soundFxCount;
	int musicSuiteCount;
	int currentSuitePlaying;
	void* BASSthread;
	int stream;
	int bassStreamPlayResult;
};
