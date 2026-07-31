#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <ELF_file>"
    exit 1
fi

file_name="$1"

if [ ! -f "$file_name" ]; then
    echo "Error: File '$file_name' does not exist."
    exit 1
fi

if ! file "$file_name" | grep -q "ELF"; then
    echo "Error: '$file_name' is not an ELF file."
    exit 1
fi

source ./messages.sh

header=$(readelf -h "$file_name")

magic_number=$(echo "$header" | awk -F': *' '/Magic:/ {print $2}')
class=$(echo "$header" | awk '/Class:/ {print $2}')
byte_order=$(echo "$header" | awk -F': *' '/Data:/ {print $2}')
entry_point_address=$(echo "$header" | awk '/Entry point address:/ {print $4}')

display_elf_header_info
