#ifndef MENU_H
#define MENU_H

#include <string>
#include <map>
#include <functional>


//forward declarations for prototypes
struct Data;
struct JPEG_Data;


std::string displayStartMessage();
std::string displayListofCommands();


//function prototypes for menu

Data readInputFile(const std::string& filePath);
void identify_jpegs(const std::string& input_filepath, const std::vector<unsigned char>& magic_bytes);
void store_all_JPEGS(const std::vector<JPEG_Data>& JPEG_Data_List, const std::string& destination_directory);

//Function mappign template
template<typename FuncType>
using FunctionMap = std::map<std::string, std::function<FuncType>>;

//Function Map definitions for menu
extern FunctionMap<void(const std::string&)> voidFunctionMap;
extern FunctionMap<Data(const std::string&)> dataFunctionMap;
#endif // !MENU_H
