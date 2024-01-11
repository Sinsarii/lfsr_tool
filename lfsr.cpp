#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <map>
#include <string>
#include <filesystem>
/*
* 


*/

/*
	get_head()

	read the magic bytes and then get the pointer


*/

namespace fs = std::filesystem;

struct Data
{
	unsigned char* array;

	int array_length;
};

struct JPEG_Data
{
	unsigned char* jpeg_data;

	unsigned char* MD5_hash;

	std::string file_path;

	int offset;

	int data_length;

	int image_height;
	
	int image_width;
};

struct Entry
{
	//Name of entry
	std::string name = "";

	//pointer to block list
	int32_t block_list_pointer = 0;

	//block list
	std::map<int16_t, int32_t> block_list;
	//combined encrypted data of block list
	unsigned char* encryptedData;

	//decrypted data of combined block list
	unsigned char* decryptedData;

	//length of combined data
	int dataLength = 0;

};

std::vector<Entry> Entry_List_Vector;

bool check_if_null_terminator(unsigned char* encrypted_data, int32_t pointer)
{
	if (encrypted_data[pointer] == 255 &&
		encrypted_data[pointer + 1] == 255 &&
		encrypted_data[pointer + 2] == 255 &&
		encrypted_data[pointer + 3] == 255)
	{
		return true;
	}
	return false;
}


int32_t getEntryListPointer(unsigned char* encryptedData, int32_t &pointer)
{

	int step_counter = 0;

	int32_t current_pointer = 0;
	int32_t temp_pointer = 0;

	//get rid of leading 0's
	for (pointer; encryptedData[pointer] == '\0'; pointer++)
	{
		if (encryptedData[pointer] != '\0')
		{
			break;
		}
	}

	//dynamically create the pointer, making sure it is less than the size of the array it is stored in
	for (int i = 0; i < sizeof(int32_t); ++i, pointer++)
	{
		//if the first number we hit is the last number before the ending signifier, make a pair with a leading 0
		if (i == 0 && (encryptedData[pointer + 1] == '\0' && encryptedData[pointer + 2] == '\0'))
		{
			current_pointer |= (static_cast<std::int32_t>(encryptedData[pointer - 1]) << (i * 8));
			current_pointer |= (static_cast<std::int32_t>(encryptedData[pointer]) << ((i + 1) * 8));
			break;

		}
		current_pointer |= (static_cast<std::int32_t>(encryptedData[pointer]) << (i * 8));
		if (encryptedData[pointer + 1] == '\0' && encryptedData[pointer + 2] == '\0')
		{
			break;
		}
	}

	pointer += 2;
	return current_pointer;

	/*

	for (int i = 0; i < sizeof(int32_t); ++i, pointer++)
	{
		//if the only grab 1 value, make sure there is a leading 0
		current_pointer |= (static_cast<std::int32_t>(encryptedData[pointer]) << (i * 8));
		if (encryptedData[pointer + 1] == '\0' && encryptedData[pointer + 2] == '\0')
		{
			pointer += 2;
			break;
		}
	}


	//every pointer ends with '\0','\0'

	//skip the zeroes until we find a non zero
	
	//dynamically build the int32 untill we find the 0,0 then end
	return current_pointer;
	*/
}

void getEntryListVector(unsigned char* encryptedData, int32_t pointer)
{
	const unsigned int ENDING_POINT = 0xFFFFFFFF;
	const int MAX_ENTRIES = 127;

	std::int32_t current_index = pointer;
	std::int32_t starting_index = pointer;

	while (Entry_List_Vector.size() < MAX_ENTRIES && current_index < ENDING_POINT)
	{
		unsigned char block_list_pointer[4] = { 0x0, 0x0, 0x0, 0x0 };
		char current_name[16] = { 0 };  // Initialize current_name with null characters
		std::int32_t current_pointer = 0;

		// Grab each entry
		// Name is a char[16] null terminated
		// Get int32 pointer
		// char[16] + int32 = 20 indices of the encrypted data

		// Iterate to grab the name
		for (int i = 0; i < 16 && encryptedData[current_index] != '\0'; ++i, ++current_index)
		{
			current_name[i] = static_cast<char>(encryptedData[current_index]);
		}
		// Increment and iterate to grab the pointer
		//current_index += 2;
		//starting_index = current_index;
		current_index++;

		current_pointer = getEntryListPointer(encryptedData, current_index);

		Entry currentEntry;

		currentEntry.name = current_name;
		currentEntry.block_list_pointer = current_pointer;

		Entry_List_Vector.push_back(currentEntry);

		current_index++;
		if (check_if_null_terminator(encryptedData, current_index))
		{
			break;
		}
		starting_index = current_index;
	}
}

std::map<std::string, int32_t> getEntryList(unsigned char* encryptedData, int32_t pointer)
{
	std::map<std::string, int32_t> ENTRY_LIST;
	const unsigned int ENDING_POINT = 0xFFFFFFFF;
	const int MAX_ENTRIES = 127;
	std::int32_t current_index = pointer;
	std::int32_t starting_index = pointer;

	while (ENTRY_LIST.size() < MAX_ENTRIES && current_index < ENDING_POINT)
	{
		unsigned char block_list_pointer[4] = { 0x0, 0x0, 0x0, 0x0 };
		char current_name[16] = { 0 };  // Initialize current_name with null characters
		std::int32_t current_pointer = 0;

		// Grab each entry
		// Name is a char[16] null terminated
		// Get int32 pointer
		// char[16] + int32 = 20 indices of the encrypted data

		// Iterate to grab the name
		for (int i = 0; i < 16 && encryptedData[current_index] != '\0'; ++i, ++current_index)
		{
			current_name[i] = static_cast<char>(encryptedData[current_index]);
		}
		// Increment and iterate to grab the pointer
		//current_index += 2;
		//starting_index = current_index;
		current_index++;

		current_pointer = getEntryListPointer(encryptedData, current_index);


		ENTRY_LIST[std::string(current_name)] = current_pointer;
	
		current_index++;
		if (check_if_null_terminator(encryptedData, current_index))
		{
			break;
		}
		starting_index = current_index;
	}

	return ENTRY_LIST;
}

int32_t get_head_pointer(unsigned char* encrypted_data)
{
	//MAGIC = "CT2018"
	unsigned char MAGIC[] = { 0x43, 0x54, 0x32, 0x30, 0x31, 0x38 };
	unsigned char pointer[] = {0x0,0x0,0x0,0x0};
	int32_t ENTRY_LIST_POINTER = 0;
	for (int i = 0; i < 6; i++)
	{
		if (encrypted_data[i] != MAGIC[i])
		{
			std::cerr << "Incorrect Header " << std::endl;
		}
	}
	//if it is correct, read the next 4 entries, starting at entry 6
	for (int i = 0; i < 4; i++)
	{
		pointer[i] = encrypted_data[i+6];
	}
	//pointer is in little-endian byte order, read the byte order in reverse and form the int32 value
	for (int i = 0; i < 4; i++)
	{
		ENTRY_LIST_POINTER |= (pointer[i] << (i * 8));
	}
	return ENTRY_LIST_POINTER;
}

unsigned int lfsr(unsigned int seed)
{
	const unsigned int FEEDBACK_VALUE = 0x87654321;

	//find the lowest bit (least significant bit lsb)
	unsigned int lsb = seed & 1;
	//seed is always shifted once
	seed >>= 1;
	//if the lsb is 1, take shifted seed and XOR it with the feedback value
	if (lsb)
	{
		seed ^= FEEDBACK_VALUE;
	}
	return seed;
}

unsigned char* Crypt(unsigned char* data, int dataLength, unsigned int initialValue)
{
	//create output array
	unsigned char* obfuscatedData = new unsigned char[dataLength];

	unsigned int seed = initialValue;
	//iterate over each element of the array
	for (int i = 0; i < dataLength; i++)
	{
		unsigned char element = data[i];
		//do 8 steps of the lfsr
		for (int steps = 0; steps < 8; steps++)
		{
			seed = lfsr(seed);
		}
		//use produced seed and grab the lowest bit which is our key
		unsigned int key = seed & 0xFF;
		//XOR key with the character
		unsigned char obfuscated = element ^ key;
		//print the result
		obfuscatedData[i] = obfuscated;
	}
	//if the lowerst bit of 

	return obfuscatedData;
}

void seedTest()
{
	unsigned int seed = 0xFFFFFFFF;
	for (int steps = 0; steps < 8; steps++)
	{
		seed = lfsr(seed);
	}
}

//takes in the file, iterators over it, and returns a character array to be worked on
unsigned char* readFile(std::string filePath)
{
	/*
	std::ifstream file(filePath, std::ios::binary | std::ios_base::in);
	if (!file.is_open())
	{
		std::cerr << "Failed to open the file " << filePath << std::endl;
		return 0;
	}

	//get the amount of characters in the file
	file.seekg(0, std::ios_base::end);
	int dataLength = static_cast<int>(file.tellg());
	file.seekg(0, std::ios_base::beg);

	//read file and store it in char array
	unsigned char* data = new unsigned char[dataLength];

	file.read(reinterpret_cast<char*>(data), dataLength);[

	file.close();

	return data;
	*/

	std::ifstream file(filePath, std::ios::binary);

	if (!file)
	{
		std::cerr << "Failed to open the file " << filePath << std::endl;
		return 0;
	}

	std::vector<char> encryptedInput;
	char character;
	while (file.get(character))
	{
		encryptedInput.push_back(character);
	}
	file.close();

	//convert vector to unsigned char* array
	const int size = encryptedInput.size();
	unsigned char* data = new unsigned char[size];
	for (int i = 0; i < size; i++)
	{
		data[i] = encryptedInput[i];
	}
	return data;
}

void outputToFile(unsigned char* data, int dataLength, std::string filepath)
{
	std::ofstream file(filepath, std::ios::binary);
	if (!file.is_open())
	{
		std::cerr << "Failed to open file: " << filepath << std::endl;
		return;
	}

	std::copy(data, data + dataLength, std::ostreambuf_iterator<char>(file));
	file.close();
	/*
	* possibly not type safe, probably shouldn't use
	* 
	file.write(reinterpret_cast<char*>(data), dataLength);
	file.close();
	*/

}

void printArray(unsigned char* decodedArray, int size)
{
	for (int i = 0; i < size; i++)

	{
		std::cout << decodedArray[i];
	}
	std::cout << std::endl;
}

void printArrayHex(unsigned char* decodedArray, int size)
{
	for (int i = 0; i < size; i++)
	{
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(decodedArray[i]) << " ";
	}
	std::cout << std::endl;
}

void printArrayText(unsigned char* decodedArray, int size)
{

}

void challenge1()
{
	//std::string inputString = "apple";
//std::string inputString = "\xCD\x01\xEF\xD7\x30";
	std::string inputFile = "test.txt";

	int dataLength = 5;
	unsigned int initialValue = 0x12345678;
	//unsigned int initialValue = 0x4F574154;
	unsigned char* data = readFile(inputFile);
	//convert string into unsigned char array

	/*
	unsigned char* data = new unsigned char[dataLength];
	for (int i = 0; i < dataLength; i++)
	{
		data[i] = static_cast<unsigned char>(inputString[i]);
	}
	*/
	unsigned char* modifiedData = Crypt(data, dataLength, initialValue);
	outputToFile(modifiedData, dataLength, "output.txt");
	printArray(modifiedData, dataLength);
	printArrayHex(modifiedData, dataLength);
	//for each character in the input string we need to run the ofuscation


	//seedTest();
}
std::int32_t get_block_data_pointer(unsigned char* encryptedData, int32_t pointer)
{
	int32_t block_data_pointer = 0;

	for (int i = 0; i < sizeof(int32_t); i++)
	{
		block_data_pointer |= (static_cast<std::int32_t>(encryptedData[pointer + i]) << (i * 8));
	}
	
	return block_data_pointer;
}

std::int16_t get_block_size(unsigned char* encryptedData, int32_t pointer)
{
	int16_t block_size = 0;

	for (int i = 0; i < sizeof(int16_t);i++)
	{
		block_size |= (static_cast<std::int16_t>(encryptedData[pointer + i]) << (i * 8));
	}
	return block_size;
}

std::map<std::int16_t, int32_t> get_Block_List(unsigned char* encryptedData, std::int32_t pointer)
{
	//ending value is 0xFFFFFFFF
	std::map<std::int16_t, int32_t> BLOCK_LIST;
	do
	{
		int16_t block_size = get_block_size(encryptedData, pointer);
		int32_t block_data_pointer = get_block_data_pointer(encryptedData, pointer + sizeof(block_size));
		BLOCK_LIST[block_size] = block_data_pointer;
	} while (check_if_null_terminator(encryptedData, pointer += 8));

	return BLOCK_LIST;
}

void get_Block_List_All(unsigned char* encryptedData)
{
	for (Entry& current_entry: Entry_List_Vector)
	{
		current_entry.block_list = get_Block_List(encryptedData, current_entry.block_list_pointer);
	}
}

std::map<std::string, std::map<std::int16_t, int32_t>> get_Block_Master_List(unsigned char* encryptedData, std::map<std::string, int32_t> entryList)
{
	std::map<std::string, std::map<std::int16_t, int32_t>> BLOCK_MASTER_LIST;
	std::map<std::int16_t, int32_t> BLOCK_LIST;
	
	//ending value of list is 0xFFFFFFFF

	for (auto i = entryList.begin(); i != entryList.end(); i++)
	{
		std::string entry_name = i->first;
		std::int32_t pointer = i->second;
		BLOCK_LIST = get_Block_List(encryptedData, pointer);
		BLOCK_MASTER_LIST[entry_name] = BLOCK_LIST;
	}

	return BLOCK_MASTER_LIST;
}


unsigned char* get_block_data_segment(unsigned char* encryptedData, int16_t block_size, int32_t block_pointer)
{
	unsigned char* encryptedDataSegment = new unsigned char[block_size];

	for (int16_t i = 0; i < block_size; i++, block_pointer++)
	{
		encryptedDataSegment[i] = encryptedData[block_pointer];
	}

	return encryptedDataSegment;
}

unsigned char* get_block_data(unsigned char* encryptedData,std::map<std::int16_t, int32_t> block_list)
{
	//need to get the length of the combined data
	int16_t data_length = 0;

	for (auto i = block_list.begin(); i != block_list.end(); i++)
	{
		data_length += i->first;
	}

	unsigned char* block_data = new unsigned char[data_length];

	int16_t rolling_size = 0;

	for (auto i = block_list.begin(); i != block_list.end(); i++)
	{
		unsigned char* block_data_segment = new unsigned char[i->first];
		block_data_segment = get_block_data_segment(encryptedData, i->first, i->second);
		memcpy(block_data + rolling_size, block_data_segment, i->first);
		rolling_size += i->first;
	}

	return block_data;

	//
}

std::pair<unsigned char*,int16_t> get_block_data_and_size(unsigned char* encryptedData, std::map<std::int16_t, int32_t> block_list)
{
	//need to get the length of the combined data
	int16_t data_length = 0;

	for (auto i = block_list.begin(); i != block_list.end(); i++)
	{
		data_length += i->first;
	}

	unsigned char* block_data = new unsigned char[data_length];

	int16_t rolling_size = 0;

	for (auto i = block_list.begin(); i != block_list.end(); i++)
	{
		unsigned char* block_data_segment = new unsigned char[i->first];
		block_data_segment = get_block_data_segment(encryptedData, i->first, i->second);
		memcpy(block_data + rolling_size, block_data_segment, i->first);
		rolling_size += i->first;
	}

	return std::make_pair(block_data, data_length);

	//
}

void get_Block_Data_Vector(unsigned char* encryptedData)
{
	for (Entry& current_entry : Entry_List_Vector)
	{
		auto data_and_size = get_block_data_and_size(encryptedData, current_entry.block_list);
		current_entry.encryptedData = data_and_size.first;
		current_entry.dataLength = data_and_size.second;
	}
}

std::map<std::string, unsigned char*> get_block_data_masterlist(unsigned char* encryptedData, std::map<std::string, std::map<std::int16_t, int32_t>> block_master_list, std::map<std::string,Entry>& ENTRY_LIST_DATA)
{
	std::map<std::string, unsigned char*> block_data_masterlist;

	for (auto i = block_master_list.begin(); i != block_master_list.end(); i++)
	{
		block_data_masterlist[i->first] = get_block_data(encryptedData, i->second);
		ENTRY_LIST_DATA[i->first].encryptedData = get_block_data(encryptedData, i->second);
	}

	return block_data_masterlist;
}

void decrypt_block_data()
{
	const unsigned int INITIAL_VALUE = 0x4F574154;


	for (Entry& current_entry : Entry_List_Vector)
	{
		current_entry.decryptedData = Crypt(current_entry.encryptedData, current_entry.dataLength, INITIAL_VALUE);
	}
}




unsigned char* readKDB(std::string inputFile)
{
	unsigned char* encryptedData = readFile(inputFile);

	//get KDB HEAD which contains the pointer for to the ENTRY_LIST
	int32_t ENTRY_LIST_POINTER = get_head_pointer(encryptedData);
	std::map<std::string, Entry> ENTRY_LIST_DATA;
	//read and store the entry list (array of entries)
	std::map<std::string, std::int32_t> ENTRY_LIST = getEntryList(encryptedData, ENTRY_LIST_POINTER);
	getEntryListVector(encryptedData, ENTRY_LIST_POINTER);
	//read each entry which has pointer to the ENTRY'S BLOCK_LIST
	std::map<std::string, std::map<std::int16_t, int32_t>> BLOCK_MASTER_LIST = get_Block_Master_List(encryptedData, ENTRY_LIST);
	get_Block_List_All(encryptedData);
	//store the BLOCK_LIST for each entry, which is an array of BLOCKS
	std::map<std::string, unsigned char*> BLOCK_DATA_MASTERLIST = get_block_data_masterlist(encryptedData, BLOCK_MASTER_LIST, ENTRY_LIST_DATA);
	get_Block_Data_Vector(encryptedData);
	//read each block to get pointer to data and size of data
	decrypt_block_data();
	//combine all blocks and the decode[[

	//decrypt data

	return 0;
}

void load_jpeg_data()
{
	std::string KDB_Filepath;
	//get path to KDB File
	std::cout << "KDB Filepath: ";
	std::cin >> KDB_Filepath;
	std::cout << std::endl;

	std::string INPUT_Filepath;
	//get filepath from second input
	std::cout << "Second Filepath: ";
	std::cin >> INPUT_Filepath;
	std::cout << std::endl;

	//read kdb file and use ENTRY "MAGIC" data as magic bytes

	//
}


unsigned char* get_magic_bytes()
{
	for (Entry current_entry : Entry_List_Vector)
	{
		if (current_entry.name == "MAGIC")
		{
			return current_entry.decryptedData;
		}
	}
}
/*
bool bytes_found(std::vector<unsigned char>& input_file_data, std::vector<unsigned char> magic_bytes, int current_index)
{
	for (int i = current_index; i < magic_bytes.size() + current_index; i++)
	{
		if (input_file_data[i] != magic_bytes[i - current_index])
		{
			return false;
		}
	}
	return true;
}


unsigned char* get_jpeg_data(std::vector<unsigned char>& input_file_data, std::vector<unsigned char> ending_bytes, int current_index)
{

	for (int i = current_index; i < input_file_data.size(); i++)
	{
		if (input_file_data[i] == ending_bytes[0])
		{
			if (bytes_found(input_file_data, ending_bytes, i))
			{
				size_t data_size = (i - current_index + ending_bytes.size()) * sizeof(unsigned char);
				unsigned char* jpeg_data = new unsigned char[data_size];
				std::memcpy(jpeg_data, &input_file_data[current_index], data_size);
				return jpeg_data;

			}
		}
	}

	return NULL;
}

std::vector<JPEG_Data> detect_JPEGs(std::vector<unsigned char>& input_file_data, std::vector<unsigned char> magic_bytes, std::vector<unsigned char> ending_bytes)
{
	std::vector<JPEG_Data> JPEG_Data_List;

	for (int i = 0; i < input_file_data.size(); i++)
	{
		if (input_file_data[i] == magic_bytes[0])
		{
			if (bytes_found(input_file_data, magic_bytes, i))
			{
				JPEG_Data Entry;
				Entry.jpeg_data = get_jpeg_data(input_file_data, ending_bytes, i);
				JPEG_Data_List.push_back(Entry);
			}
		}
	}

	return JPEG_Data_List;
}
*/

bool magic_bytes_found(unsigned char*& data, std::vector<unsigned char> magic_bytes, int current_index)
{
	for (int i = current_index; i < magic_bytes.size() + current_index; i++)
	{
		if (data[i] != magic_bytes[i - current_index])
		{
			return false;
		}
	}
	return true;
}
JPEG_Data get_jpeg_entry(Data input_file_data, std::vector<unsigned char> ending_bytes, int current_index)
{
	JPEG_Data entry;

	for (int i = current_index; i < input_file_data.array_length; i++)
	{
		if (input_file_data.array[i] == ending_bytes[0])
		{
			if (magic_bytes_found(input_file_data.array, ending_bytes, i))
			{
				int length = (i + ending_bytes.size()) - current_index;
				//unsigned char* jpeg_data = new unsigned char[length];

				entry.jpeg_data = new unsigned char[length];

				//std::copy(input_file_data.array + current_index, input_file_data.array + current_index + length, entry.jpeg_data);

				memcpy(entry.jpeg_data, input_file_data.array + current_index, length);

				entry.data_length = length;
				return entry;

			}
		}
	}
	entry.data_length = NULL;
	return entry;
}

void repair_JPEG(JPEG_Data &Jpeg)
{
	Jpeg.jpeg_data[0] = 0xFF;
	Jpeg.jpeg_data[1] = 0xD8;
	Jpeg.jpeg_data[2] = 0xFF;
}

std::vector<JPEG_Data> store_JPEGs(Data input_File_Data, std::vector<unsigned char> magic_bytes, std::vector<unsigned char> ending_bytes)
{
	std::vector<JPEG_Data> JPEG_Data_List;

	for (int i = 0; i < input_File_Data.array_length; i++)
	{
		if (input_File_Data.array[i] == magic_bytes[0])
		{
			if (magic_bytes_found(input_File_Data.array, magic_bytes, i))
			{
				JPEG_Data Entry;
				Entry = get_jpeg_entry(input_File_Data, ending_bytes, i);
				Entry.offset = i;
				repair_JPEG(Entry);
				JPEG_Data_List.push_back(Entry);
			}
		}
	}

	return JPEG_Data_List;
}

Data readInputFile(std::string filepath)
{
	std::ifstream file(filepath, std::ios::binary);

	Data fileInput;

	if(!file)
	{
		std::cerr << "Failed to open the file " << filepath << std::endl;

		fileInput.array = NULL;

		fileInput.array_length = NULL;

		return fileInput;
	}

	file.seekg(0, std::ios::end);
	std::streampos fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	char* charBuffer = new char[fileSize];

	file.read(charBuffer, fileSize);


	fileInput.array = new unsigned char[fileSize];
	std::memcpy(fileInput.array, charBuffer, fileSize);
	fileInput.array_length = static_cast<int>(fileSize);

	delete[] charBuffer;

	return fileInput;


}

std::vector<unsigned char> readJPEGFile(std::string filePath)
{

	std::ifstream file(filePath, std::ios::binary);
	std::vector<unsigned char> encryptedInput;

	int file_length = 0;

	if (!file)
	{
		std::cerr << "Failed to open the file " << filePath << std::endl;
		return encryptedInput;
	}

	char character;
	while (file.get(character))
	{
		encryptedInput.push_back(character);
		file_length++;
	}
	file.close();

	Data file_input;

	return encryptedInput;
}

void printEntry(JPEG_Data JPEG_Entry)
{
	for (int i = 0; i < JPEG_Entry.data_length; i++)
	{
		std::cout << JPEG_Entry.jpeg_data[i];
	}
	std::cout << std::endl;
}

void get_image_dimensions(JPEG_Data &JPEG_Entry)
{
	//SOF Start of Frame marker for JPEGS

	std::vector<unsigned char> SOF = { 0xFF, 0xC0 };

	for (int i = 0; i < JPEG_Entry.data_length; i++)
	{
		if ((JPEG_Entry.jpeg_data[i] == SOF[0]) && (JPEG_Entry.jpeg_data[i + 1] == SOF[1]))
		{
			//length bytes are next pair
			std::vector<unsigned char> segment_length = { JPEG_Entry.jpeg_data[i + 3], JPEG_Entry.jpeg_data[i + 4]};
			//next byte is segment precision, skip
			//next par is segment width
			std::vector<unsigned char> segment_height = { JPEG_Entry.jpeg_data[i + 6], JPEG_Entry.jpeg_data[i + 7] };
			//next pair is segment height
			std::vector<unsigned char> segment_width = { JPEG_Entry.jpeg_data[i + 8], JPEG_Entry.jpeg_data[i +9] };
			JPEG_Entry.image_height = (static_cast<uint16_t>(segment_height[1]) << 8) | segment_height[0];
			JPEG_Entry.image_width = (static_cast<uint16_t>(segment_width[1]) << 8) | segment_width[0];
			break;
		}
	}
}

void store_JPEG(JPEG_Data jpeg_entry, std::string destination_directory)
{

	fs::create_directory(destination_directory);
	std::string filename = std::to_string(jpeg_entry.offset) + ".jpeg";
	std::string file_path = destination_directory + "/" + filename;
	std::ofstream outfile(file_path, std::ios::binary);
	outfile.write(reinterpret_cast<const char*>(jpeg_entry.jpeg_data), jpeg_entry.data_length);
}

void store_all_JPEGS(std::vector<JPEG_Data> JPEG_Data_List, std::string destination_directory)
{
	for (JPEG_Data entry : JPEG_Data_List)
	{
		store_JPEG(entry, destination_directory);
	}
}

void identify_jpegs(std::string input_filepath, unsigned char* magic_bytes)
{
	/*	
	std::vector<unsigned char> input_file_data = readJPEGFile(input_filepath);

	std::vector<unsigned char> ending_bytes = { 0xFF,0xD9 };

	std::vector<unsigned char> magic_bytes_vector = { 0x4D, 0x42, 0x4B };

	std::vector<JPEG_Data> JPEG_Data_List = detect_JPEGs(input_file_data, magic_bytes_vector, ending_bytes);

	//grab jpeg and replace starting bytes
	*/

	std::string outputFolder = input_filepath + "_Repaired";

	Data inputFileData = readInputFile(input_filepath);

	std::vector<unsigned char> ending_bytes = { 0xFF,0xD9 };

	std::vector<unsigned char> magic_bytes_vector = { 0x4D, 0x42, 0x4B };

	std::vector<JPEG_Data> JPEG_Data_List = store_JPEGs(inputFileData, magic_bytes_vector, ending_bytes);
	
	for (JPEG_Data& entry : JPEG_Data_List)
	{
		//printEntry(entry);
		get_image_dimensions(entry);

	}

	store_all_JPEGS(JPEG_Data_List, outputFolder);
}

int main()
{
	//challenge1();
	readKDB("magic.kdb");

	unsigned char* magic_bytes = get_magic_bytes();

	identify_jpegs("input.bin", magic_bytes);
	return 0;
}