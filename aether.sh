#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
rest='\033[0m'

check_dependencies() {
    local dependencies=("curl" "wget" "tar" "unzip")
    for dep in "${dependencies[@]}"; do
        if ! dpkg -s "${dep}" &> /dev/null; then
            echo -e "${yellow}Installing ${dep}...${rest}"
            pkg install "${dep}" -y
        fi
    done
}

install_aether() {
    if command -v aether &> /dev/null; then
        echo -e "${green}Aether is already installed.${rest}"
        return
    fi

    echo -e "${green}Updating packages...${rest}"
    pkg update -y && pkg upgrade -y
    check_dependencies

    local termux_arch
    termux_arch=$(dpkg --print-architecture)
    local target_arch=""

    case "$termux_arch" in
        aarch64) target_arch="arm64" ;;
        arm|armhf|armeabi*) target_arch="armv7" ;;
        x86_64|amd64) target_arch="x86_64" ;;
        *) 
            echo -e "${red}Unsupported architecture: $termux_arch${rest}"
            return 1 
            ;;
    esac

    echo -e "${green}Detected architecture: ${yellow}$termux_arch${green} -> Matching asset: ${yellow}$target_arch${rest}"
    echo -e "${green}Fetching latest release from GitHub...${rest}"
    
    DOWNLOAD_URL=$(curl -s https://api.github.com/repos/CluvexStudio/Aether/releases/latest | \
                   grep "browser_download_url" | \
                   grep -i "android" | \
                   grep -i "$target_arch" | \
                   grep -v ".sha256" | \
                   cut -d '"' -f 4 | head -n 1)

    if [ -z "$DOWNLOAD_URL" ]; then
        echo -e "${red}Failed to find a compatible Android-$target_arch release asset.${rest}"
        return 1
    fi

    FILE_NAME=$(basename "$DOWNLOAD_URL")
    echo -e "${green}Downloading $FILE_NAME...${rest}"
    wget -O "$FILE_NAME" "$DOWNLOAD_URL"

    if [[ "$FILE_NAME" == *.zip ]]; then
        unzip -o "$FILE_NAME"
    elif [[ "$FILE_NAME" == *.tar.gz ]] || [[ "$FILE_NAME" == *.tgz ]]; then
        tar -xzf "$FILE_NAME"
    fi

    BINARY_PATH=""
    if [ -f "aether" ]; then
        BINARY_PATH="aether"
    else
        BINARY_PATH=$(find . -maxdepth 1 -type f -executable -not -name "*.sh" | head -n 1)
    fi

    if [ -n "$BINARY_PATH" ]; then
        chmod +x "$BINARY_PATH"
        cp "$BINARY_PATH" "$PREFIX/bin/aether"
        echo -e "${green}Aether installed successfully. Run it by typing: aether${rest}"
        rm -f "$FILE_NAME"
    else
        echo -e "${red}Could not find the executable binary in the extracted files.${rest}"
    fi
}

uninstall_aether() {
    if [ -f "$PREFIX/bin/aether" ]; then
        rm -f "$PREFIX/bin/aether"
        echo -e "${green}Aether successfully uninstalled.${rest}"
    else
        echo -e "${yellow}Aether is not installed.${rest}"
    fi
}

clear
echo -e "${green}=== Aether Termux Installer ===${rest}"
echo -e "1) Install Aether (Auto-Detect Arch)"
echo -e "2) Uninstall Aether"
echo -e "0) Exit"
echo -ne "${green}Select option [0-2]: ${rest}"
read -r choice

case "$choice" in
    1) install_aether ;;
    2) uninstall_aether ;;
    0) exit 0 ;;
    *) echo -e "${red}Invalid option.${rest}" ;;
esac
