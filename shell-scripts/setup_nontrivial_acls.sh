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
## ./setup_nontrivial_acls.sh "superAdminADGroup" /volumes/datapool/ds01
###############################################################################

created=06/25/20013
updated=08/12/2014
version=0.0.2 ## Bump incremental version number on every change.
debug=1

## Commands used throughout the script. We do not set a path here.
AWK_CMD=/usr/bin/awk
CHGRP_CMD=/usr/sun/bin/chgrp
CHMOD_CMD=/usr/sun/bin/chmod
LS_CMD=/usr/sun/bin/ls
GETENT_CMD=/usr/bin/getent
ZFS_CMD=/usr/sbin/zfs

args=("$@") ## Args we collect from the command line.
groupname=${args[0]}
filepath=${args[1]}
default_admin_group="Domain Admins" ## Default Domain Administrators
groupid=
snapdir_is_visible=false

## Declare functions used in the main portion of the script ##

function usage () {

	printf "Usage: %s\n" " $0 <Name of Active Directory/POSIX Group> <Path to dataset/directory>"
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

	if [[ ${#args[@]} -ne 2 ]]; then
		return 1
	fi

}

function check_snapdir_visible () {
		local ds=$1 # Function should get a correctly formatted ZFS dataset string.
		[[ -z $ds ]] && return 1

		# Determine if snapdir is visible or hidden, store visibility property in
		# prop variable.
		read dir _ prop _ < <(${ZFS_CMD} get -H snapdir ${ds})

		# Return 0 if visible, 1 otherwise. Should only ever be visible or hidden.
		[[ "${prop}" == "visible" ]] && return 0 || return 1

}

function set_snapdir_hidden () {

	# If visible, snapdir should be hidden.
  local zfs_ds=${p//\/volumes\/}  # This is an ugly assumption.

  if check_snapdir_visible ${zfs_ds}; then
      print_info "Hiding snapshot directories for the duration of this script"
      ${ZFS_CMD} set snapdir=hidden ${zfs_ds}
			snapdir_is_visible=true # Set snapdir visible flag, so we know to change it later.
	fi

return

}

function set_snapdir_visible () {

	# Check flag here and so other stuff to get back to original state.
	# For Aaron to fill-in...
	return
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

	${CHMOD_CMD} -R A=owner@:rwxpcCosRrWaAdD:fd:allow,group@:rwxcsRaD:fd:allow,everyone@:aRcs:fd:allow "${filepath}" \
	|| local retcode=1

	${CHMOD_CMD} -R A+group:"${groupname}":rwxpd-aARWc--s:fd-----:allow "${filepath}" \
	|| local retcode=1

	[[ ${debug} -gt 1 ]] && set +x
	return ${retcode}
}

## Begin main portion of the script ##

check_number_of_args || { print_error "Cannot continue, fewer or greater than expected number of arguments passed." && usage; }

get_numeric_id_from_group_name || { print_error "Cannot continue, check group name (# getent group)." && usage; }

check_snapdir_visible

set_zfs_acl_handling_props && print_info "Successfully changed ZFS aclmode and aclinherit to passthrough." \
|| print_error "Unable to change ZFS metadata. "

reset_nontrivial_acl  && print_info "Successfully reset Non-trivial ACL to defaults." \
|| print_error "Failed to reset Non-trivial ACL to defaults."

set_group_owner_acls "${groupid}" && print_info "Successfully set ${groupname} ACLs on dataset." \
|| print_error "Failed to set ${groupname} ACLs on dataset."

set_domain_admin_acls && print_info "Successfully set Domain Admins ACLs on dataset." \
|| print_error "Failed to set Domain Admins ACLs on dataset."

## set snapdir value back to its original value
zfs set snapdir="${checksnapdir}" "${filepath}"

printf "%s\n" "---- Begin Results ----"
${LS_CMD} -ldaV "${filepath}"
printf "%s\n" "---- Begin Results ----"
