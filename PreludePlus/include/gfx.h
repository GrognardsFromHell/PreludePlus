#include <windows.h>
#include <d3d.h>
struct TextureDef;

namespace gfx {

	struct Unk5 {
		BYTE data[32];
	};

	struct Gfx {
		int height;
		int width;
		float someFactor; //inited at 11.5, possibly view angle?
		BOOL windowed;
		int bitDepth;
		int filtering;
		HINSTANCE hInstance;
		HWND hWnd;
		void* ddraw;
		void* backbufferClipper;
		void* clipper;
		int yMax;
		int field_30;
		int xMax;
		int field_38;
		void* ddrawPrimarySurf;
		void* backBuffer;
		void* zbuf;
		void* d3dDevice;
		void* d3d;
		int rgbBitCountMaybe;
		int gotHAL;
		D3DMATRIX worldMatrix;
		short colorKey;
		short field_9A;
		D3DMATRIX projectionMat;
		TextureDef* currentTexture;
		D3DMATERIAL7 basicMaterials[9];
		void* fontEngine;
		RECT cursorSrcRects[10];
		int field_3E8[52]; //unks
		TextureDef * circles[3];
		int field_4C4[145];
		int cursorFramesCounts[12];
		int cursorFrameIdx;
		int cursorType;
		int someCountIdx;
		int someCount;
		int cursorX[12];
		int cursorY[12];
		Unk5 field_7A8[4];
		int field_828;
		void* cursorTexture;
		int cursorRelated_CyclesAt3;
		int field_834[3];
		int field_840;
	};


	class GfxSystem {
		Gfx* Get();
	};
}
