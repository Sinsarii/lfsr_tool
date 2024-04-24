#include <iostream>
#include <map>
#include <functional>
#include <string>
#include "menu.h"

//menu display

std::string displayStartMessage()
{
	std::cout << "LFSR_tool Loaded, type 'help' for list of commands or 'exit' to close";
    return "";
}

FunctionMap<void(const std::string&)> voidFunctionMap = {
    {"identifyJpegs", identify_jpegs},
    {"storeAllJpegs", store_all_JPEGS},
    {"exit", [](const std::string&) {
        std::cout << "Exiting program." << std::endl;
        exit(0);
    }}
};
FunctionMap<Data(const std::string&)> dataFunctionMap = {

    {"readFile", readInputFile}
};
std::string displayListofCommands()
{
    std::cout << "Menu:\n";
    std::cout << "1. Read File\n";
    std::cout << "2. Identify JPEGs\n";
    std::cout << "3. Store all JPEGs\n";
    std::cout << "4. Exit\n";
    std::cout << "Enter your choice: ";

    std::string choice;
    std::cin >> choice;
    return choice;

}




