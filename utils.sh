#!/bin/bash

#declare -rg 
# LOG_PATH="/var/log/"
declare -rg DEFAULT_MSG="loading..."
# values for SSHPASS
declare -g rm_ip
declare -g rm_user
declare -g rm_pass
declare -g rm_port
declare -rg SSH_PORT=22

# Color variables
RED="\e[\033[1;31m"
GREEN="\e[\033[1;32m"
YELLOW="\e[\033[1;33m"
BLUE="\e[\033[1;34m"
MAGENTA="\e[\033[1;35m"
CYAN="\e[\033[1;36m"
WHITE="\e[\033[1;37m"
NC="\e[\033[0m"
NBC="\e[\033[49m"
GR="\e[\033[1;32;41m"


print_color() {
    local color_code="$1"
    local message="$2"
    echo -e "${color_code}${message}${NC}"
}

prefixed_message() {
	local prefix="$1"
    local color_code="$2"
    local message="$3"
    echo -e "${GREEN}${prefix}${color_code}${message}${NC}"
}

fail() {
	[ $# -eq 0 ] && fail "Invalid use of \"fail\" function"
	[ $# -eq 1 ] && echo -e "${RED}[!] $1${NC}" && exit 1
	
	local msg=$1
	local rm_func=$2
	shift 2
	[ -z "$(declare -F $rm_func)" ] && fail "The passed function ($rm_func) isn't a valid function"

	echo "${RED}[!] $msg${NC}" && $rm_func $@ && exit 1

}

check_permissions() {
    # Numeric representation of desired permissions: rwx (read, write, execute)
    local desired_permissions=7

    # Get numeric representation of current directory permissions
    local current_permissions=$(stat -c '%a' .)

    [ "$current_permissions" -lt "$desired_permissions" ] && fail "You do not have sufficient permissions in this directory!"
}

# Function to cycle through a pattern and make a wave with a given word
# Parameters:
#	word to make a wave to it
cycle_word_and_chars() {
	local user_input=$1 #""
	# for x in "$@"; do
	# 	user_input="$user_input$x"
	# done
	local -r user_input=${user_input,,}
	local -r word="${user_input:-$DEFAULT_MSG}"
	local -r chars="-\|/"
	local -r spaces="      "
		
	local j=0

	# echo $2


	while true; do
		for (( i=0; i< ${#word}; i++ )); do
			[[ ! ${word:i:1} =~ [[:alpha:]] ]] && continue
				
			curr_word="${word:0:i}$(echo ${word:i:1} | tr '[:lower:]' '[:upper:]')${word:i+1}"

			# echo "${word:i:1}"
			# echo $curr_word

			local overwrite_length=$((${#curr_word}+1))

			# echo $word
			# echo $curr_word
			echo -ne "$curr_word${chars:j:1}"
			# echo -ne "${CYAN}$curr_word${chars:j:1} ${NC}"
			tput cub $overwrite_length

			(( j = (j + 1) % ${#chars} ))
			sleep .1
			read -r -n 1 -t .001 -s && break 2 
		done
	done
	echo -e "\r$word$spaces" #space is used to remove the cycling char
}

# Function to make a wave with a given word
# Parameters:
#	word to make a wave to it
cycle_word() {
	local user_input=${1,,}
	local word="${user_input:-$DEFAULT_MSG}"
	while true; do
		for (( i=0; i< ${#word}; i++ )); do
			curr_word="${word:0:i}$(echo ${word:i:1} | tr '[:lower:]' '[:upper:]')${word:i+1}"
			printf "%s\r" "$curr_word"
			read -r -n 1 -t .1 -s && break 2
		done
	done
	echo -e "$word"
}

# Function to cycle through a pattern 
cycle_char() {
	local chars="-\|/"
	local word=$1
	while true; do
		for (( i=0; i< ${#chars}; i++ )); do
			echo -ne "\r$word${chars:i:1}"
			read -r -n 1 -t .1 -s && break 2
		done
	done
	echo
}

# Function to check for internet connectivity without getting blocked
check_connectivity() {
	nslookup google.com > /dev/null && return 0
	fail "No internet connection available!"
}

# Function to check the validity of the given target address
# Parameters:
#	$1: The given target address
# Return:
#	0 if the input is valid
#	1 if the input is invalid
check_domain_format() {
	local user_input=$1
	[[ $user_input =~ $IP_PATTERN || $user_input =~ $DOMAIN_PATTERN ]] && echo "$user_input" && return 0 || return 1
}

# Function to create a new audit
audit() {
	echo "$(date)- $1" >> "$LOG_PATH"
}

# Function to create a new audit and display to the std
tee_audit() {
	echo "$1"
	audit "$1"
}

# Function to check if an app is already installed
# Parameters:
#	$1: app name to check
check_installed() {
	if dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; then
		audit "[#] $1 is already installed."
		prefixed_message "[#] " "$CYAN" "$1 is already installed."
		return 0  
	else
		audit "[#] $1 isn't installed."
		return 1  
	fi
}

# Function to Loop through the programs array and check/install each program
# Paramets:
#	$1: array of function to install
install_programs() {
	prefixed_message "[*] " "$BLUE" "Checking Installations"
	local array=("$@")

	for program in "${array[@]}"; do
		# Skip installation if program is already installed
		check_installed "$program" && continue 
			
		cycle_word_and_chars "[*] Installing $program..." &
		local load_msg_pid=$!
		
		(
			sudo apt-get update #TODO RUN ONCE
			sudo apt-get install -y "$program" 
		) &>/dev/null

		kill $load_msg_pid
		echo -e "\r[*] Installing $program... "
		audit "[*] $program has been installed"
	done
	echo
}

# Function to request the user to input the remote server credentials
# Note:
#	the password field is hidden in order to protect the user from over the sholder attacks
#	the port field may be skiped and assumed as the default
get_remote_creds() {
	read -rp "[?] Enter remote user: " rm_user
	read -s -rp "[?] Enter remote password: " rm_pass; echo
	read -rp "[?] Enter remote address: " rm_ip
	read -rp "[?] Enter remote port: " rm_port; [ -z "$rm_port" ] && rm_port=$SSH_PORT
}

ssh_wrapper() {
	[ -z "$rm_user" ] && fail "\"ssh_wrapper\""

	sshpass -p $rm_pass ssh -o StrictHostKeyChecking=no $rm_user@$rm_ip $@ 
}

