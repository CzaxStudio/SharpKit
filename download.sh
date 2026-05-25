#!/bin/bash
# First steps
mkdir Myproject
cd Myproject
# Download using .NET CLI
dotnet add package SharpKit.Offensive --version 1.0.0
dotnet add package SharpKit.Offensive --version 1.0.5
dotnet add package SharpKit.Offensive --version 1.1.0

# Download using NuGet CLI
nuget install SharpKit.Offensive -Version 1.0.0
nuget install SharpKit.Offensive -Version 1.0.5
nuget install SharpKit.Offensive -Version 1.1.0

# Download using Paket CLI
paket add SharpKit.Offensive --version 1.0.0
paket add SharpKit.Offensive --version 1.0.5
paket add SharpKit.Offensive --version 1.1.0

# Notes:

# Save as download.sh
# Make it executable: chmod +x download.sh
# Run using: ./download.sh

