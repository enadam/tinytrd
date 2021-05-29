#
# settings.sh -- read settings from a configuration file
#

# The default configuration file, can be overridden.
: ${ROOT_CONF="root.conf"};

if [ "$ROOT_CONF" != "" ];
then	# It's defined, let's load it.
	if expr index "$ROOT_CONF" / > /dev/null || [ ! -f "$ROOT_CONF" ];
	then	# $ROOT_CONF contains a slash or should be found in the $PATH.
		source "$ROOT_CONF";
	else	# Load it from the current working directory.
		# (Unlike bash, busybox sh doesn't allow that without a slash.)
		source "./$ROOT_CONF";
	fi
fi

# Exit with an error message.
error() {
	echo "$@" >&2;
	exit 1;
}

# Verify that the settings being used by the caller are defined and not empty,
# otherwise apply defaults if possible.
using() {
	local setting;

	for setting;
	do
		eval local defined=\${$setting:+DEFINED};
		[ "$defined" ] \
			&& continue;

		# $setting is not defined, do we have a default?
		case "$setting" in
		MOUNT_DIR)
			MOUNT_DIR="/rootfs";;
		DM_DEV)	# Leave it empty if $ROOT_DEV is not encrypted.
			[ "$CRYPTSETUP" = "none" ] \
				|| DM_DEV="rootfs";;
		ROOT_MODE)
			ROOT_MODE="auto";;
		CRYPTSETUP)
			CRYPTSETUP="luks";;
		CIPHER_ALGO)
			CIPHER_ALGO="akarmi";;
		*)
			error "$0: $setting is undefined";;
		esac
	done
}

# Make sure the specified settings are defined, even if empty.
defined() {
	local setting;

	for setting;
	do	# Consider $setting defined even if it's empty.
		eval local defined=\${$setting+DEFINED};
		[ "$defined" ] \
			|| error "$0: $setting is undefined";
	done
}

# If defined, verify that $file exists, otherwise bail out.
get_me() {
	local test="$1";
	local file="$2";

	if [ "$file" = ""  ];
	then
		return 1;
	elif [ "$test" "$file" ];
	then
		return 0;
	else
		error "Please get me $file.";
	fi
}

# Die if $1 is not $2.
assert() {
	local var="$1";
	local expected="$2";

	eval local actual=\$$var;
	[ "$actual" = "$expected" ] \
		|| error "$0: \$$var ($actual) != \"$expected\"";
}

# Sleep for a while and return 1 if it was interrupted.
interruptible_sleep() {
	trap "return 1" INT;
	sleep "$@";
	trap INT;
}

# Call a user-provided function or external program if defined/exists.
call() {
	if type "$1" > /dev/null;
	then
		"$@";
	fi
}

# End of settings.sh
