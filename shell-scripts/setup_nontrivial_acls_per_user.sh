#!/usr/bin/bash

# The MIT License (MIT)
# Copyright (c) 2013 RackTop Systems.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
###############################################################################
## Description: 
###############################################################################
## Script is used to set proper non-trivial ACLs on ZFS datasets and files/dirs.
## The idea behind this script is to allow for a more simplified share 
## administration, without having to manage the share via a Windows system.
## Script was mainly created to support proper configuration of shares used for
## AFP and CIFS together.
## The script assumes that directory mapping is working correctly and that we 
## are able to do lookups of groups in the directory. At the moment there is no 
## assumption that ldap works correctly, but we must be able to perform 
## `getent group <groupname>` and get a meaningful answer. This answer is then
## parsed and group ID is extracted. Various chmod, chown, etc. commands are
## assuming existing group ID.
###############################################################################
## Usage:
###############################################################################
## To use this script, simply pass name of group as first argument and 
## and the filesystem path, starting at the root, which at the moment is
## typically `/volumes`.
## Resulting command should look very similar to the following:
## ./setup_nontrivial_acls_per_user.sh \
## "username" "Group Owner" /path/to/directory
###############################################################################

name=setup_nontrivial_acls_per_user.sh
created=06/25/2013
updated=07/25/2013
version=0.0.1 ## Bump incremental version number on every change.
debug=0

## Commands used throughout the script. We do not set a path here.
AWK_CMD=/usr/bin/awk
CHGRP_CMD=/usr/sun/bin/chgrp
CHMOD_CMD=/usr/sun/bin/chmod
CHOWN_CMD=/usr/sun/bin/chown
LS_CMD=/usr/sun/bin/ls
GETENT_CMD=/usr/bin/getent

args=("$@") ## Args we collect from the command line.
username=${args[0]}
groupname=${args[1]}
filepath=${args[2]}
default_admin_group="Domain Admins" ## Default Domain Administrators
groupid=
userid=

## Declare functions used in the main portion of the script ##

function usage () {

	printf "Usage: %s\n" " $0 <Name of AD/POSIX User> <Name of AD/POSIX Group> </path/to/directory>"
	exit 1
}

function print_error () {
	local msg=$@
	printf "[ERROR] %s\n" "${msg}"
}

function print_info () {
	local msg=$@
	printf "[INFO] %s\n" "${msg}"
}

function print_debug () {

	local msg=$@
	[[ ${debug} -gt 0 ]] && printf "[DEBUG] %s\n" "${msg}"
}


function reset_nontrivial_acl () {

	local retcode=0
	print_debug ">> reset_nontrivial_acl <<"
	set -x
	${CHMOD_CMD} -R A- "${filepath}" || local retcode=1
	set +x
	return ${retcode}
}

function check_number_of_args () {

	if [[ ${#args[@]} -ne 3 ]]; then
		return 1
	fi

}


function set_zfs_acl_handling_props () {

	## If this is a ZFS dataset, we will try to set aclinherit and aclmode to
	## passthrough.

	[[ ${debug} -gt 1 ]] && set -x
	local retcode=0
	print_debug ">> set_zfs_acl_handling_props <<"

	local zfs_ds=$( echo "${filepath}"| ${AWK_CMD} '{gsub("^/volumes/", ""); print}' )
	zfs list -Ho name ${zfs_ds} 2>/dev/null && local __iszfsdataset=yes

	[[ ${__iszfsdataset} == "yes" ]] && zfs set aclmode=passthrough "${zfs_ds}"
	[[ $? -ne 0 ]] && local retcode=1

	[[ ${__iszfsdataset} == "yes" ]] && zfs set aclinherit=passthrough "${zfs_ds}"
	[[ $? -ne 0 ]] && local retcode=1

	[[ ${debug} -gt 1 ]] && set +x
	return ${retcode}	
}


function get_numeric_id_from_group_name () {

	[[ ${debug} -gt 1 ]] && set -x
	local retcode=0
	print_debug ">> get_numeric_id_from_group_name <<"

	groupid=$(${GETENT_CMD} group "${groupname}"|awk -F":" '{print $3}')

	print_debug "Group ID: ${groupid}"

	[[ -z ${groupid} ]] && local retcode=1

	[[ ${debug} -gt 1 ]] && set +x
	return ${retcode}
}


function get_numeric_id_from_user_name () {

	[[ ${debug} -gt 1 ]] && set -x
	local retcode=0
	print_debug ">> get_numeric_id_from_user_name <<"

	userid=$(${GETENT_CMD} user "${username}"|awk -F":" '{print $3}')

	print_debug "User ID: ${userid}"

	[[ -z ${userid} ]] && local retcode=1

	[[ ${debug} -gt 1 ]] && set +x
	return ${retcode}
}


function set_domain_admin_acls () {

	[[ ${debug} -gt 1 ]] && set -x
	local retcode=0
	print_debug ">> set_domain_admin_acls <<"

	${CHMOD_CMD} -R A+group:"${default_admin_group}":rwxpcCosRrWaAdD:fd:allow "${filepath}" \
	|| local retcode=1

	[[ ${debug} -gt 1 ]] && set +x
	return ${retcode}

}


function set_group_owner_acls () {

	[[ ${debug} -gt 1 ]] && set -x
	local retcode=0
	print_debug ">> set_group_owner_acls <<"
	
	local groupid=$1
	${CHGRP_CMD} -R ${groupid} "${filepath}" || local retcode=1
	${CHOWN_CMD} -R "${username}" "${filepath}" || local retcode=1

	${CHMOD_CMD} -R A=owner@:rwxpcCosRrWaAdD:fd:allow,group@:rwxcsRaD:fd:allow,everyone@:aRcs:fd:allow "${filepath}" \
	|| local retcode=1

	## If the group is root, i.e. "Domain Admins", we should skip this setting,
	## because the root group is already being set in the `set_domain_admin_acls` function.
	if [[ "${groupname}" != "Domain Admins" && "${groupname}" != "root"  ]]; then
		${CHMOD_CMD} -R A+group:"${groupname}":rwxpd-aARWc--s:fd-----:allow "${filepath}" \
		|| local retcode=1
	fi
	${CHMOD_CMD} -R A+user:"${username}":rwxpd-aARWc--s:fd-----:allow "${filepath}" \
	|| local retcode=1


	[[ ${debug} -gt 1 ]] && set +x
	return ${retcode}
}

## Begin main portion of the script ##

check_number_of_args || { print_error "Cannot continue, fewer or greater than expected number of arguments passed." && usage; }

get_numeric_id_from_group_name || { print_error "Cannot continue, check group name (# getent group)." && usage; }

set_zfs_acl_handling_props && print_info "Successfully changed ZFS aclmode and aclinherit to passthrough." \
|| print_error "Unable to change ZFS metadata. "

reset_nontrivial_acl  && print_info "Successfully reset Non-trivial ACL to defaults." \
|| print_error "Failed to reset Non-trivial ACL to defaults."

set_group_owner_acls "${groupid}" && print_info "Successfully set ${groupname} ACLs on dataset." \
|| print_error "Failed to set ${groupname} ACLs on dataset."

set_domain_admin_acls && print_info "Successfully set Domain Admins ACLs on dataset." \
|| print_error "Failed to set Domain Admins ACLs on dataset."


printf "%s\n" "---- Begin Results ----"
${LS_CMD} -ldaV "${filepath}"
printf "%s\n" "---- Begin Results ----"

