#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>

// GKey holds the previous and saves for the future the cipher state for each decryption event.
// It is seeded with an initial value in SpawnKey() and saved after each Decrypt() call as each
// prevous rotation of the cipher is required for the next Decrypt() in the decryption chain.
// 
// Both count and hold have unsigned values from 0-255, as they represent indexes on the key, they
// are intended to overflow.
struct GKey
{
	uint8_t key[0x100];
	uint8_t count;
	uint8_t hold;
};

// Part of Microsoft PE struct
// documented here https://msdn.microsoft.com/en-au/library/ms809762.aspx
// & https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format
// and in WINNT.h
struct IMAGE_FILE_HEADER
{
	uint16_t machine;
	uint16_t num_sections;
	uint32_t timestamp;
	uint32_t symboltable_rva;
	uint32_t num_symbols;
	uint16_t sizeof_optionalheader;
	uint16_t characteristics;
};
struct IMAGE_OPTIONAL_HEADER32
{
	uint16_t magic;
	uint8_t  major_linker_version;
	uint8_t  minor_linker_version;
	uint32_t sizeof_code;
	uint32_t sizeof_initialized_data;
	uint32_t sizeof_uninitialized_data;
	uint32_t addressof_entrypoint;
};
struct IMAGE_NT_HEADERS
{
	uint32_t signature;
	IMAGE_FILE_HEADER fileheader;
	IMAGE_OPTIONAL_HEADER32 optionalheader;
};
struct IMAGE_IMPORT_DESCRIPTOR
{
	uint32_t import_lookup_table_rva;
	uint32_t timestamp;
	uint32_t forwarder_chain;
	uint32_t name_rva;
	uint32_t import_address_table_rva;
};
struct IMAGE_IMPORT_BY_NAME
{
	uint16_t hint;
	uint8_t name[1];
};
struct IMAGE_DATA_DIRECTORY 
{
	uint32_t va;
	uint32_t size;
};

void ReadFile(
	const char* in,
	const char* mode,
	uint8_t** out,
	int* len);

void WriteFile(
	const char* name,
	const void* data,
	size_t len);

void Decrypt(
	GKey* gk,
	const void* in,
	void* out,
	size_t len);

void SpawnKey(
	GKey* gk,
	const uint8_t* seed,
	size_t len);

void ReadFile(
	const char* in,
	const char* mode,
	uint8_t** out,
	int* len)
{
	FILE* f = fopen(in, mode);

	if (f == NULL || fseek(f, 0, SEEK_END))
		return;

	*len = ftell(f);

	if (*len == -1) {
		fclose(f);
		return;
	}

	*out = (uint8_t*)malloc(*len);

	fseek(f, 0, SEEK_SET);
	if (fread(*out, 1, *len, f) != *len) {
		fclose(f);
		return;
	}

	fclose(f);
	return;
}

void WriteFile(
	const char * name,
	const void * data,
	size_t len)
{
	FILE* f = fopen(name, "wb");

	if (f == NULL) {
		printf("Error writing file\n");
		return;
	}

	size_t r = fwrite(data, 1, len, f);

	if (r != len)
		printf("Error writing file\n");

	fclose(f);
	return;
}

// Decrypts the {len} size byte array at {in} and writes it to {out},
// advances {gk} with every byte decrypted
void Decrypt(
	GKey* gk,
	const void* in,
	void* out,
	size_t len)
{
	uint8_t t1, t2;
	uint8_t j;

	// Each byte is decrypted one by one
	for (uint32_t i = 0; i < len; i++) {

		// Persisted count from GKey is incremented first
		gk->count++;
		j = gk->count;

		// Persisted carry (hold) value is added to from the value at key[count]
		gk->hold += gk->key[j];

		// The values at key[count] and key[hold] are swapped with eachother
		t1 = gk->key[j];
		t2 = gk->key[gk->hold];
		gk->key[j] = t2;
		gk->key[gk->hold] = t1;

		// The value of key[count] is added to key[hold]. Unsigned overflow is intended
		t1 += t2;

		// in[i] represents the current byte being decrypted
		// it is xored with the the value at key[t1]
		// t1 being the result of adding key[hold] to key[count]
		// the result is stored in out[i] which may or may not be the same address of in[i]
		((uint8_t*)out)[i] = ((uint8_t*)in)[i] ^ gk->key[t1];
	}
}

// Spawns the GKey to be used to in Decrypt() from an initial seed value
void SpawnKey(
	GKey* gk,
	const uint8_t* seed,
	size_t len)
{
	// Initial state for key is successively incrementing bytes from 0-FF
	for (int i = 0; i < 0x100; i++) {
		gk->key[i] = i;
	}

	// The key is jumbled by the seed given
	// seed[i] is xored with 0xFF, added to key[i], then left shifted by 0x1
	// result is added into h, which may be non-zero from the previous loop
	// key[i] and key[h] are swapped and the loop is continued
	uint8_t h = 0;
	for (int i = 0; i < 0x100; i++) {
		uint8_t j, k;
		j = gk->key[i];
		k = seed[i % len];	
		k ^= 0xFF;
		k += j;
		k <<= 0x1;
		h += k;
		gk->key[i] = gk->key[h];
		gk->key[h] = j;
	}
}

int main() {

	// Read stub and league binaries into memory

	int len = 0, slen = 0;
	uint8_t* league;
	uint8_t* stub;

	ReadFile("League of Legends.exe", "rb", &league, &len);
	ReadFile("stub.dll", "rb", &stub, &slen);

	if (!slen || !len) 
	{
		printf("We need both \"League of Legends.exe\" and \"stub.dll\" for this to work\n");
		return 0;
	}

	// -------
	// Stage 0 - Check if unpacking the correct version

	uint32_t* header_offset = (uint32_t*)(league + 0x3C);
	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(league + *header_offset);

	if (nt_header->fileheader.timestamp != 0x5B5A36FC) {
		printf("Wrong version of League of Legends.exe, we require 8.14 stub patch 2 (28 July)\n");
		return 0;
	}

	// -------
	// Stage 1 - Unpacking initial .text bytes into the intermediate 1st decrypted state

	// Keep in mind these are offsets on the file, not RVAs

	// We need a pointer to the .text section in League of Legends.exe
	uint8_t* ltext = league + 0x1000;

	// Length is not obfuscated in the PE header and can be read from there instead of being
	// static here
	size_t ltext_len = 0x10BF000;

	// Pointer and length of the seed for the first GKey decryption chain
	uint8_t* decrypt1_seed = stub + 0x3DBC18;
	size_t decrypt1_seed_len = 0xB1;

	// RITO (lol) magic number
	uint8_t* decrypt1_magic = league + 0x17CE040;
	size_t decrypt1_magic_len = 0x4;

	// This is the seed for the second and final stage of .text decryption
	uint8_t* decrypt2_seed = stub + 0x3DD554;
	size_t decrypt2_seed_len = 0x3B;

	// Declare a GKey gk, zero it and spawn our key with the seed
	GKey gk;
	memset(&gk, 0, sizeof(GKey));
	SpawnKey(&gk, decrypt1_seed, decrypt1_seed_len);

	// Decrypt the magic number
	uint8_t rito[4];
	Decrypt(&gk, decrypt1_magic, rito, decrypt1_magic_len);

	// Decrypt the entire .text section
	Decrypt(&gk, ltext, ltext, ltext_len);

	// -------
	// Stage 2 - Import decryption

	// Pointers to the 'real' Import Table the one pointed to by the PE header is garbage
	// and to an array of name lengths stored in stub.dll
	IMAGE_IMPORT_DESCRIPTOR* import_descriptor_ptr = (IMAGE_IMPORT_DESCRIPTOR*)(league + 0x13D4B10);
	uint32_t* import_name_len_ptr = (uint32_t*)(stub + 0x36D330);

	// For later to fix PE header
	size_t iat_len = 0;

	// There are 19 imports
	for (int i = 0; i < 0x13; i++) 
	{
		// Read the first import descriptor in the import descriptor table.
		// 0x14 is the size of each struct
		Decrypt(&gk, import_descriptor_ptr, import_descriptor_ptr, 0x14);

		// stub.dll has an array of name lengths; get the first one
		size_t len = *import_name_len_ptr;

		// decrypt the pointer to the import name
		uint8_t* name_ptr = league + import_descriptor_ptr->name_rva;
		Decrypt(&gk, name_ptr, name_ptr, len);

		// name_ptr is now a null terminated string containing the path of the import
		// (eg. BugSplat.dll)

		// get pointer to the IAT and ILT
		uint32_t* iat_ptr = (uint32_t*)(league + import_descriptor_ptr->import_address_table_rva);
		uint32_t* ilt = (uint32_t*)(league + import_descriptor_ptr->import_lookup_table_rva);

		// Walk the import lookup table until we hit NULL
		uint32_t hintarray_rva;
		do {
			// decrypt the address of the lookup table 
			Decrypt(&gk, ilt, ilt, 0x4);

			// deref the decrypted ILT entry
			// this is an rva to a hint/name struct
			hintarray_rva = *(uint32_t*)ilt;

			// IMAGE_ORDINAL_FLAG32 is the most signicant bit (0x80000000)
			// if this is set there is no function name to decrypt
			if (hintarray_rva && !(hintarray_rva & 0x80000000)) {

				// get our real pointer
				IMAGE_IMPORT_BY_NAME* hint_ptr = (IMAGE_IMPORT_BY_NAME*)(league + hintarray_rva);

				// increment the stub name length array ptr
				import_name_len_ptr++;

				// +2 because I guess they didn't add in the extra size of the struct? 
				// I'm not sure why they did this
				len = *(import_name_len_ptr)+0x2;

				// decrypt the IMAGE_IMPORT_BY_NAME at hint_ptr
				Decrypt(&gk, hint_ptr, hint_ptr, len);
			}

			// Decrypt the IAT entry, it should be 0
			Decrypt(&gk, iat_ptr, iat_ptr, 0x4);

			// Put rva into IAT
			*iat_ptr = hintarray_rva;

			// Increment the pointers for next loop
			iat_ptr++;
			ilt++;
			iat_len += 0x4;

		} while (hintarray_rva); // end when we hit NULL 

		// go to the next import_descriptor
		import_descriptor_ptr++;
		// increment the pointer for the next import name len
		import_name_len_ptr++;

	} // end of IAT loading loop

	// Reconstruct the exe image

	nt_header->optionalheader.addressof_entrypoint = 0x102A692;

	// TODO: Expand PE struct to include this
	// 0x78 is the offset to the IMAGE_DATA_DIRECTORY array
	uint8_t* pe = league + *header_offset + 0x78;

	// 1 and 12 are the indexes of ENTRY_IMPORT and ENTRY_IAT in the IMAGE_DATA_DIRECTORY array
	IMAGE_DATA_DIRECTORY* idt =
		(IMAGE_DATA_DIRECTORY*)(pe + (sizeof(IMAGE_DATA_DIRECTORY) * 1));
	IMAGE_DATA_DIRECTORY* iat =
		(IMAGE_DATA_DIRECTORY*)(pe + (sizeof(IMAGE_DATA_DIRECTORY) * 12));

	// Size remains OK
	idt->va = 0x13D4B10;

	// The VA of the IAT is at the top of .rdata
	iat->va = 0x10C0000;
	iat->size = iat_len;

	// give execute and read permission to .text
	// PE + 0x78 + 0xA4 is the permissions of the first section which should be from .text
	uint32_t* text_characteristics = (uint32_t*)(pe + 0xA4);
	*text_characteristics = 0x60000020;

	// -------
	// Stage 3 - .text second decryption

	// .text pages are all encrypted separately to allow non-sequential decryption
	// 4096 byte page size
	uint32_t num_pages = ltext_len / 0x1000;

	// loop for each page, starting at 1
	for (uint32_t i = 1; i <= num_pages; i++) 
	{
		// zero out or create a new GKey for each page
		memset(&gk, 0, sizeof(GKey));

		// the decrypt2 seed is 0xXX in length but there are 0xYY of them
		// the modulus of the page number against 0xYY is whichever one is used
		uint8_t* seed = decrypt2_seed + ((i % 0xA2) * decrypt2_seed_len);

		// pointer to our specific page
		uint8_t* text = league + (i * 0x1000);

		// create a key for this new GKey to use on this page
		SpawnKey(&gk, seed, decrypt2_seed_len);

		// decrypt the page in place
		Decrypt(&gk, text, text, 0x1000);
	}

	// -------
	// Stage 4 - .reloc

	// the relocation section has been moved from .reloc but not encrypted
	// it is used after stage 2 decryption of each page in .text to relocate addresses

	IMAGE_DATA_DIRECTORY* reloc =
		(IMAGE_DATA_DIRECTORY*)(pe + (sizeof(IMAGE_DATA_DIRECTORY) * 5));

	// file offset to .reloc
	uint8_t* reloc_ptr = league + 0x1721000;
	size_t reloc_size = reloc->size;

	// location of moved .reloc
	uint8_t* stub_ptr = league + 0x17CE000;
	stub_ptr += 0xB3A;

	// copy into proper reloc
	memcpy(reloc_ptr, stub_ptr, reloc_size);

	WriteFile("League of Legends_unpacked.exe", league, len);

	// end
	free(league);
	free(stub);
	return 0;
}