#!/bin/bash
# set -x
################################################################################
#                                                                              #
# WF.sh																	       #
#                                                                              #
# version: 1.0.0                                                               #
#                                                                              #
# Network Research - Remote target scanning using tor and a remote server      #
#																			   #
# Srudent Name - Michael Ivlev												   #
# Student Code - S11														   #
# Class Code - HMagen773616													   #
# Lectures Name - Eliran Berkovich											   #
#																			   #
# GNU GENERAL PUBLIC LICENSE                                                   #
#                                                                              #
# This program is free software: you can redistribute it and/or modify         #
# it under the terms of the GNU General Public License as published by         #
# the Free Software Foundation, either version 3 of the License, or            #
# (at your option) any later version.                                          #
#                                                                              #
# This program is distributed in the hope that it will be useful,              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of               #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                #
# GNU General Public License for more details.                                 #
#                                                                              #
# You should have received a copy of the GNU General Public License            #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.        #
#                                                                              #
################################################################################

# Import utils script
declare -rg SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
source "$SCRIPT_DIR/utils.sh"

# Define the programs to check and install
declare -rga programs=("libimage-exiftool-perl" "binwalk" "binutils" "foremost" "bulk-extractor" "tshark" "zip" "git") #TODO Volotility
# Define the paths
# script_dir="$(dirname '$0')"
# [[ $script_dir == "." ]] && script_dir=$(pwd)
declare -rg VOL_DIR="./volatility3"
declare -rg VOL_PATH="./volatility3/vol.py"
# path to the scripts log file
declare -rg LOG_PATH="/var/log/wf.log"
# get user name
declare -rg USERNAME="${SUDO_USER:-$USER}"
# path to saved scans
declare -rg SCAN_PATH="$(pwd)" #"$(grep -w $USERNAME /etc/passwd | cut -d: -f 6)/Documents"
# flag for different echo style
# is_cow_time=false


# Function to display the correct way to run the script
usage() {
	local script_name=$(basename "$0")
cat << EOF
Usage: $script_name [Options] {target_file}
-h Describe how to run the script
-r Revert the network setting (i.e. before routing trafic through the tor network)
-m Choose the remote level of abstraction:
	0 localhost 
	1 lan range
	2 public ip range 
	3 hidden service
 
EOF
}

# Function to check the init condition
init_checks() {
	[ $UID -ne 0 ] && fail "This script requires root privileges. Please run with sudo." && exit 1
	[ ! -d "$SCAN_PATH" ] && mkdir "$SCAN_PATH"
	[ ! -f "$LOG_PATH" ] && sudo touch "$LOG_PATH"

	[ $# -eq 0 ] && fail "This script requires an argument for the target file"
	
	while getopts ":h" opt; do # TODO more flags (for sshapss creds)
		case $opt in
			h)
				usage
				exit 0
				;;
			\?)
				fail "Invalid option: -$OPTARG" usage
				;;
		esac
	done

	shift $((OPTIND - 1))
}

check_target() {
	[ ! -f "$1" ] && fail "the file ($1) doesn't exist"
	# local ext="${1##*.}"
	# [ "$ext" != "mem" ] && [ "$ext" != "dd" ] && fail "Invalid file format (.$ext)"
	local filetype=$(file -b --mime-encoding "$1")
	[ "$filetype" == "binary" ] || fail "Invalid file encoding ($filetype)"
	echo -e "${GREEN}[*] ${BLUE}File $1 exists\n${NC}"
}

use_user_privileges() {
	sudo -u "$USERNAME" "$@"
}

install_vol() {
	[ -d "$VOL_DIR" ] && return 0
	# echo -e "${GREEN}[+]${CYAN} Installing volatility..."

	(
		sudo -u "$USERNAME" git clone https://github.com/volatilityfoundation/volatility3.git
		#FIXME works only in cli #chown -R "$USERNAME:$USERNAME" "$VOL_DIR"
		pip3 install -r "$VOL_DIR/requirements.txt"
	) &>/dev/null

	# local checksums="$VOL_DIR/volatility3/symbols/checksum.txt"
	# wget -O "$checksums" https://downloads.volatilityfoundation.org/volatility3/symbols/SHA256SUMS

	# wget -O "$VOL_DIR/volatility3/symbols/windows.zip" https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip --check-certificate --input-file="$checksums"
	# wget -O "$VOL_DIR/volatility3/symbols/mac.zip" https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip --check-certificate --input-file="$checksums"
	# wget -O "$VOL_DIR/volatility3/symbols/linux.zip" https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip --check-certificate --input-file="$checksums"

	# find ./volatility3/volatility3/symbols -name '*.zip' -print0 | xargs -0 -I {} unzip {} -d ./volatility3/volatility3/symbols/
	# rm "./volatility3/volatility3/symbols/*.zip"
	
}

decorated_install_vol() {
    with_loading_animation "Installing volatility... " \
		install_vol
}

# Define a function to add prefix message and loading animation
function with_loading_animation() {
    local msg="$1"
    shift

    echo -ne "${GREEN}[+] ${CYAN}"
    cycle_word_and_chars "$msg" &
    local loading_msg_pid=$!

	"$@" &>/dev/null  # Suppress the command's output

    kill $loading_msg_pid
    echo -ne "\r${GREEN}[+] ${CYAN}"
    echo -e "$msg    "
}

run_exiftool() {
	exiftool -a "$target_file" > "$EXIF_PATH"
}

run_binwalk() {
	binwalk -B "$target_file" > "$BINWALK_PATH"
}

# Decorate the functions
decorated_run_exiftool() {
    with_loading_animation "Running ExifTool" \
		run_exiftool 
}

decorated_run_binwalk() {
    with_loading_animation "Running binwalk" \
		run_binwalk 
}

decorated_run_foremost() {
    with_loading_animation "Carving with Foremost " \
		use_user_privileges foremost -t all "$target_file" -o "$FOREMOST_PATH"
}

decorated_run_bulk() {
    with_loading_animation "Carving with Bulk " \
		use_user_privileges bulk_extractor "$target_file" -o "$BULK_PATH"
}

decorated_run_strings() {
    with_loading_animation "Running Strings " \
		run_strings
}

decorated_run_vol() {
    with_loading_animation "Running Volatility " \
		run_vol
}

run_strings() {
	sudo -u "$USERNAME" touch "$STRINGS_PATH_PATTERN".txt
	sudo -u "$USERNAME" touch "$STRINGS_PATH_PATTERN"_exe.txt
	# user-agent

	strings "$target_file" > "$STRINGS_PATH_PATTERN".txt
	grep -Eo ".*\.exe" "$STRINGS_PATH_PATTERN.txt" | awk '{print $NF}' | sort -fu > "$STRINGS_PATH_PATTERN"_exe.txt
}

run_vol() {
	sudo -u "$USERNAME" touch "$VOL_LOG_PATH"_process.txt
	sudo -u "$USERNAME" touch "$VOL_LOG_PATH"_process_malicious.txt
	# sudo -u "$USERNAME" touch "$VOL_LOG_PATH"_connections.txt
	sudo -u "$USERNAME" touch "$VOL_LOG_PATH"_commands.txt
	sudo -u "$USERNAME" touch "$VOL_LOG_PATH"_registry.txt
	sudo -u "$USERNAME" touch "$VOL_LOG_PATH"_userassist.txt
	sudo -u "$USERNAME" touch "$VOL_LOG_PATH"_SAM.txt
	sudo -u "$USERNAME" touch "$VOL_LOG_PATH"_SYSTEM.txt
	sudo -u "$USERNAME" touch "$VOL_LOG_PATH"_hashes.txt
	sudo -u "$USERNAME" touch "$VOL_LOG_PATH"_accounts.txt


	# verinfo
	# vadwalk
	# vadinfo
	# svcscan
	# ssdt
	# sessions
	# hashdump # only dump2.mem
	# privileges
	# poolscanner
	# netstat # not for all mem files
	# netscan # same, #TODO use bulk_extractor
	# m*
	# malfind. This plugin will attempt to identify injected processes


	local strings_msg="Running volatility "
	echo -ne "\r${GREEN}[+] ${CYAN}"
	echo -ne "$strings_msg    "
	
	local profile=$(python3 "$VOL_PATH" -f "$target_file" windows.info 2>/dev/null | awk '/NTBuildLab/ {print $2}')

	[ -z "$profile" ] && echo -e "\r${YELLOW}[!]${CYAN} No Profile was found" && return 0

	echo -e "\r${GREEN}[+]${CYAN} Running Volatility Analysis [Profile Found: ${profile}]\n" 
	echo -e "${GREEN}[+]${CYAN} Running Memory Analysis: Process" 
	"$VOL_PATH" -f "$target_file" windows.pstree 2>/dev/null > "$VOL_LOG_PATH"_process.txt

	echo -e "${GREEN}[+]${CYAN} Running Memory Analysis: MalProcess" 
	
	process_double_link=$(mktemp)
	process_unlinked=$(mktemp)
	
	"$VOL_PATH" -f "$target_file" windows.pslist 2>/dev/null | awk 'NR>4 {print $3 " " $1 ":" $2}' | sort -V > "$process_double_link"
	"$VOL_PATH" -f "$target_file" windows.psscan 2>/dev/null | awk 'NR>4 {print $3 " " $1 ":" $2}' | sort -V > "$process_unlinked"
	diff "$process_double_link" "$process_unlinked" > "$VOL_LOG_PATH"_process_malicious.txt
	rm "$process_double_link" "$process_unlinked"

	#TODO if mal is found, dump file,dll,etc..
	# vol.py -f <dump> -o /dir/to/store_dump/ windows.memmap.Memmap --pid <suspicious PID> --dump
	# strings *.dmp | grep -i "user-agent\|http"
	# dlllist | grep -w pid | grep -w exe (first lines might give the location of mal)

	# echo -e "${GREEN}[+]${CYAN} Running Memory Analysis: Network" 
	# "$VOL_PATH" -f "$target_file" windows.connections 2>/dev/null > "$VOL_LOG_PATH"_connections.txt

	echo -e "${GREEN}[+]${CYAN} Running Memory Analysis: Commands" 
	"$VOL_PATH" -f "$target_file" windows.cmdline 2>/dev/null > "$VOL_LOG_PATH"_commands.txt

	echo -e "${GREEN}[+]${CYAN} Running Memory Analysis: Registry" 
	"$VOL_PATH" -f "$target_file" windows.registry.hivelist 2>/dev/null > "$VOL_LOG_PATH"_registry.txt

	echo -e "${GREEN}[+]${CYAN} Running Memory Analysis: UserAssist" 
	"$VOL_PATH" -f "$target_file" windows.registry.userassist 2>/dev/null > "$VOL_LOG_PATH"_userassist.txt
	
	echo -e "${GREEN}[+]${CYAN} Running Memory Analysis: SAM" 
	"$VOL_PATH" -f "$target_file" windows.registry.hivelist 2>/dev/null | awk '/\\SAM/ {print $1}' > "$VOL_LOG_PATH"_SAM.txt
	
	echo -e "${GREEN}[+]${CYAN} Running Memory Analysis: SYSTEM" 
	"$VOL_PATH" -f "$target_file" windows.registry.hivelist 2>/dev/null | awk '/\y\\system\y/ {print $1}' > "$VOL_LOG_PATH"_SYSTEM.txt
	
	# echo -e "${GREEN}[+]${CYAN} Running Memory Analysis: HashDump" 
	# "$VOL_PATH" -f "$target_file" --profile="$profile" hashdump 2>/dev/null > "$VOL_LOG_PATH"_hashes.txt
	
	echo -e "${GREEN}[+]${CYAN} Running Memory Analysis: Accounts" 
	"$VOL_PATH" -f "$target_file" windows.registry.printkey --key "SAM\Domains\Account\Users\Names" 2>/dev/null | awk 'NR>3 {sub("-", "", $6); print $6}' | awk 'NF' > "$VOL_LOG_PATH"_accounts.txt
}

get_pcap() {
	PCAP_PATH=$(find "$BULK_PATH" -name "*pcap" | head -1 )
	[ -n "$PCAP_PATH" ] && echo -e "${GREEN}[+]${CYAN} Network data Found [Path: $PCAP_PATH] [Size:$(du -h "$PCAP_PATH" | awk '{print $1}')]"
}

# Main function to run the entire script
main() {
	init_checks "$@"
	
	local target_file=$1
	check_target "$target_file"

	install_programs "${programs[@]}"
	decorated_install_vol #FIXME set owner as user (__pycache__)

	echo -e "\n${GREEN}[*] ${BLUE}Starting Analysis"


	local report_id=$(date +%s)
	EXIF_PATH="$SCAN_PATH/$report_id/exiftool.txt"
	BINWALK_PATH="$SCAN_PATH/$report_id/binwalk.txt"
	FOREMOST_PATH="$SCAN_PATH/$report_id/foremost"
	BULK_PATH="$SCAN_PATH/$report_id/bulk"
	STRINGS_PATH_PATTERN="$SCAN_PATH/$report_id/strings"
	VOL_LOG_PATH="$SCAN_PATH/$report_id/volatility"
	local REPORT_TXT_PATH="$SCAN_PATH/$report_id/report.txt"
	local ZIP_CONTENT="$SCAN_PATH/$report_id"
	
	sudo -u "$USERNAME" mkdir -p "$FOREMOST_PATH"
	sudo -u "$USERNAME" mkdir -p "$BULK_PATH"
	sudo -u "$USERNAME" touch "$EXIF_PATH"
	sudo -u "$USERNAME" touch "$BINWALK_PATH"
	# sudo -u "$USERNAME" touch "$STRINGS_PATH"
	
	decorated_run_exiftool
	decorated_run_binwalk 
	decorated_run_foremost
	decorated_run_bulk
	get_pcap
	decorated_run_strings
	run_vol

	local bulk_count=$(find "$BULK_PATH" -type f | wc -l)
	local foremost_count=$(( $(find "$FOREMOST_PATH" -type f | wc -l) - 1 ))
	local pcap_count=0; [ -f "$PCAP_PATH" ] && pcap_count=$(tshark -r "$PCAP_PATH" -q -z "io,phs" | grep -m 1 -w ip | awk '{print $2}' | awk -F: '{print $NF}')
	local strings_count=$(find "$SCAN_PATH/$report_id" -name "strings*" | wc -l )
	local vol_count=$(find "$SCAN_PATH/$report_id" -name "volatility*" | wc -l )
	local total_count=$((bulk_count + foremost_count + pcap_count + strings_count + vol_count))
	
	echo -e "\n${GREEN}[*]${CYAN} $(date) - Forensics Analysis for $target_file"
	echo -e "${GREEN}[+]${CYAN} Saved into directory:$report_id [Extracted Files: $total_count]."
	echo -e "${GREEN}[+]${CYAN} [Bulk:$bulk_count Files] [Foremost:$foremost_count Files] [Volatility:$vol_count Files] [Strings:$strings_count files] [Network:$pcap_count Packets]"
	
	# create report: (name, files extracted, etc.) 
	sudo -u "$USERNAME" touch "$REPORT_TXT_PATH"
	(
	echo -e "METADATA:"
	awk 'NR>3' "$EXIF_PATH"

	echo -e "\nFILES:" 
	find "$FOREMOST_PATH" -type f | awk -F/ '{print $NF}' 
	echo -e "\nDOMAINS:" 
	strings "$STRINGS_PATH_PATTERN.txt" | grep -Eo "http?://.*(| )" | sed 's/ /\n/g' | grep -Eo "http?://.*$" | cut -d / -f 3- | awk -F/ '{sub(/^www\./, "", $1); if ($1 && $1 ~ /\./ && $1 !~ /:/) print $1}'| sort | uniq -c | sort -nr | awk '{print $NF}' 

	# cat 1691941379/bulk/domain.txt | awk '{sub(/^www\./, "", $2); if ($2 && $2 ~ /\./)print $2}' | awk '{if($1 !~ /^[0-9]/) print $1}'| sort -u
	
	#FIXME histogram doesnt echo
	[ -f "$BULK_PATH/ip_histrogram.txt" ] && echo -e "\nIPs: (shown as histogram)" && cat "$BULK_PATH"/ip_histogram.txt
	cat "$BULK_PATH/ip_histogram.txt"

	) >> "$REPORT_TXT_PATH"


	local zip_name="Report_$report_id.zip"
	cd "$SCAN_PATH" || fail "unable to move to $SCRIPT_DIR"
	sudo -u "$USERNAME" zip -r "$zip_name" "$report_id"/* &>/dev/null
	echo -e "\n${GREEN}[*]${CYAN} Forensics analysis completed [$zip_name]"

	# say "Have a good day"
}

main "${@}"
