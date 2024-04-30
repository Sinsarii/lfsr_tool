# What is it?
lfsr_tool is an implementation of a Custom Linear Feedback Shift Register that is XOR-Shifted. Given encoded data that contains obfuscated JPEGs the purpose of this program is to identify, repair, and save all the JPEGs in a given set of data.

In this repository you'll find:
* C++ implementations of all utilities
* Utilities that decode given data
* Utilities that will parse, seperate, and hold all decoded data for a given file
* Utilities that will recreate and save the JPEGs based on currently decoded data

# Requires

* C++
    * C++17 or newer
    * Self contained, no external dependencies (only standard library functions used)
    * C++11 can be used if < filesystem > library is not used.

# Functions
* readKDB() - Reads input file and maps all data into blocks that can then be parsed and stored into a vector of found entries
