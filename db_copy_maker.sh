#!/bin/bash
# Set the source and destination directories
source_dir="/home/achille/wallet-provider"
destination_dir="/home/achille/wallet-provider/backup"

# Set the file name
file_name="db.sqlite"

# Create the destination directory if it doesn't exist
mkdir -p "$destination_dir"

# Copy the file to the destination directory and append the current date to the file name
cp "$source_dir/$file_name" "$destination_dir/$file_name_$(date +'%Y-%m-%d').sqlite"