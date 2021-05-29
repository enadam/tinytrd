#!/usr/bin/python3
#
# mkcpio.py -- generate cpio archives for tinytrd
#
# This program is like "find | cpio -o", but it does a little more: it can
# pull in the targets of symlinks marked appropriately (while leaving other
# symlinks unresolved) and it can substitute *.gpg files with their decrypted
# contents.  This way an input directory like:
#
# fs/busybox => /bin/busybox
# fs/sh => busybox
# fs/key.gpg
#
# Can be converted to this archive:
#
# fs/busybox
# fs/sh => busybox
# fs/key
#
# Where key.gpg is decrypted on the fly (with gpg -d).  For this the busybox
# symlink and key.gpg in the input directory need to be marked.  Either an
# extended attribute (XATTR_DEREF or XATTR_DECRYPT) with the value "1" must be
# placed on the file (on the symlink in case of fs/busybox) or the attributes
# can be declared in the .mkcpio file in each subdirectory:
#
# > deref busybox
# > decrypt key.gpg
#
# The lines can be in any order and the attributes may be repeated.  More than
# one file (separated by whitespace) can be listed for each attribute, and the
# file names can be quoted if they contain space.  Symlinks marked as "deref"
# must be resolvable.  You can link to directories, whose contents will be
# fully resolved.  Files marked as "decrypt" don't have to end with a .gpg
# extension (you can specify a different one with the -x option, and you can
# also change the decryption command with -D).
#
# For each input directory hierarchy mkcpio.py creates and outputs 1..3 cpio
# archives: one with all files not needing special processing (fs/sh in the
# example above), another with the files to be dereferenced if there are any
# (fs/busybox) and a last one with the decrypted GnuPG files.  .mkcpio tables
# are not included in any of them.  When concatenated, the kernel extracts all
# archives one by one.

import sys
import os, stat, errno, subprocess
import argparse, shlex

# Extended attributes marking files for special processing.  We need to use
# the trusted namespace, because attributes in the user namespace cannot be
# set on symlinks.  Unfortunately the trusted namespace is only available for
# root.
XATTR_DEREF	= "trusted.dereference"
XATTR_DECRYPT	= "trusted.decrypt"

# Also read attributes from this file in each directory.
XATTR_FILE	= ".mkcpio"

# The general cpio invocation, setting the output format which the kernel
# understands.
CPIO = [ "cpio", "-o", "-H", "newc" ]

# The default handler of "decrypt" files, and the extension to strip from
# the name of such files.
DECRYPT_CMD = [ "gpg", "-d" ]
DECRYPT_EXT = "gpg"

# Really tiny cpio-writer, used to encapsulate the contents of transparently
# decrypted files.  It speaks the same format as cpio -H newc.
class Cpio:
	MAGIC = b"070701"
	TRAILER = "TRAILER!!!"
	BLOCK_SIZE = 512

	def __init__(self, out=None):
		if out is not None:
			self.out = out
		else:	# Reopen stdout in binary mode.
			self.out = open(sys.stdout.fileno(), "wb",
					closefd=False)

		# The number of bytes written so far.  Used to know how much
		# to pad the output.
		self.offset = 0

	# Write a part of the cpio archive.
	def write(self, data):
		self.offset += self.out.write(data)

	# Pad the output to make its length divisible by @alignment.
	def pad(self, alignment=4):
		unaligned = self.offset % alignment
		if unaligned > 0:
			self.write(b'\0' * (alignment - unaligned))

	# Add a file to the archive with contents.  If @stat is not None,
	# take the uid, gid, mode and mtime from it.
	def add(self, fname, data, stat=None):
		self.write(self.MAGIC)

		# Construct the file header.
		header = [
			0,			#  0 inode
			0o100400,		#  1 mode
			0, 0,			#  2 uid, gid
			1,			#  4 nlink
			0,			#  5 mtime
			len(data),		#  6 data size
			0, 0,			#  7 dev major, minor
			0, 0,			#  9 rdev major, minor
			len(fname) + 1,		# 11 fname size
			0,			# 12 checksum
		]

		if stat:
			# Override @header fields with @stat.
			header[1] &= ~0o7777
			header[1] |= stat.st_mode & 0o7777
			header[2] = stat.st_uid
			header[3] = stat.st_gid
			header[5] = int(stat.st_mtime)

		# Write the @header.  The file name must be NUL-terminated.
		self.write((b"%08X" * len(header)) % tuple(header))
		self.write(fname.encode())
		self.write(b'\0')
		self.pad()

		self.write(data)
		self.pad()

	# Must be called after all desired files have been add()ed.
	def finish(self):
		self.add(self.TRAILER, b"")
		self.pad(self.BLOCK_SIZE)

# Parse an XATTR_FILE and return two sets of file names to be dereferenced
# or decrypted.
def get_attributes(fname):
	# Raise an exception unless the file is not found.
	try:
		attributes = open(fname)
	except OSError as err:
		if err.errno == errno.ENOENT:
			return set(), set()
		raise

	# Process the file line by line.
	deref = set()
	decrypt = set()
	for line in attributes:
		# shlex allows the user to quote file names in case they
		# contain space.
		attr, *fnames = shlex.split(line)
		if attr in ("dereference", "deref"):
			deref.update(fnames)
		elif attr == "decrypt":
			decrypt.update(fnames)
		else:
			raise ValueError(
				"%s: %s: unknown attribute"
				% (attributes.name, attr))
	return deref, decrypt

# Return wheter @fname has the extended @attr:ibute with value == "1".
def has_attr(fname, attr):
	try:
		val = os.getxattr(fname, attr, follow_symlinks=False)
	except OSError as err:
		if err.errno in (errno.EOPNOTSUPP, errno.ENODATA):
			return False
		raise
	else:
		return val == b"1"

# Strip @top and any connecting slashes from the start of @path.
def path_for_cpio(top, path):
	assert path.startswith(top)
	return path[len(top):].lstrip("/")

def add_path_to_cpio(cpio, top, path):
	print(path_for_cpio(top, path), file=cpio.stdin)

# Tell the @cpio subprocess that we've finished and check its exit status.
def finish_cpio(cpio):
	cpio.stdin.close()
	if cpio.wait() != 0:
		raise Exception(
			"cpio exited with status %d" % cpio.returncode)

# Create cpio archives for the @top directory.
def mkcpio(top, args):
	def raise_exception(exc):
		raise exc

	# First create an archive containing all files under @top not needing
	# special processing.
	print("Processing %s..." % top, file=sys.stderr)
	cpio = subprocess.Popen(CPIO, cwd=top,
		stdin=subprocess.PIPE, universal_newlines=True)

	# Walk the directory hierarchy, remembering the files needing special
	# processing.  Other files are passed to @cpio for archival.
	deref = [ ]
	decrypt = [ ]
	for directory, dirs, files in os.walk(top, onerror=raise_exception):
		deref_this_dir, decrypt_this_dir = get_attributes(
			os.path.join(directory, XATTR_FILE))
		if args.include_encrypted:
			# Only dereference encrypted files, don't decrypt them.
			deref_this_dir.update(decrypt_this_dir)
			decrypt_this_dir = set()

		for fname in dirs:
			path = os.path.join(directory, fname)
			if fname in deref_this_dir \
					or has_attr(path, XATTR_DEREF):
				deref.append(path)
				continue
			add_path_to_cpio(cpio, top, path)

		for fname in files:
			if fname == XATTR_FILE:
				# Don't include it in the archive.
				continue

			path = os.path.join(directory, fname)
			if fname in deref_this_dir \
					or has_attr(path, XATTR_DEREF):
				deref.append(path)
				continue
			elif fname in decrypt_this_dir \
					or has_attr(path, XATTR_DECRYPT):
				if not args.exclude_encrypted:
					decrypt.append(path)
				continue

			add_path_to_cpio(cpio, top, path)
	finish_cpio(cpio)

	# Create another archive with dereferenced files.
	if deref:
		cpio = subprocess.Popen(
			CPIO + [ "--dereference" ], cwd=top,
			stdin=subprocess.PIPE, universal_newlines=True)
		for path in deref:
			add_path_to_cpio(cpio, top, path)
			if not stat.S_ISDIR(os.stat(path).st_mode):
				continue

			# @path is a directory, walk() it.
			for directory, dirs, files in os.walk(path,
					followlinks=True,
					onerror=raise_exception):
				for fname in dirs + files:
					path = os.path.join(directory, fname)
					add_path_to_cpio(cpio, top, path)
		finish_cpio(cpio)

	# And another one with decrypted file contents.
	if decrypt:
		cpio = Cpio()
		for path in decrypt:
			# Decrypt @path.
			gpg = subprocess.run(
				DECRYPT_CMD + [ path ], check=True,
				stdout=subprocess.PIPE)

			# Strip @DECRYPT_EXT from the @path.
			dst = path
			if DECRYPT_EXT and path.endswith(f".{DECRYPT_EXT}"):
				dst = path[:-len(DECRYPT_EXT)-1]

			# Add it to the archive.
			cpio.add(path_for_cpio(top, dst), gpg.stdout,
					None if args.root_owner
					else os.stat(path))
		cpio.finish()

# Main starts here.
parser = argparse.ArgumentParser(
	description="Generate cpio archives for tinytrd.")
parser.add_argument("--root", "-R", dest="root_owner", action="store_true",
	help="Make the files in the archives owned by root.  Useful if "
		"the script is run by a non-root user.")

mutex = parser.add_mutually_exclusive_group()
mutex.add_argument("--include-encrypted", "-I", action="store_true",
	help="Don't decrypt files, just include them encrypted.")
mutex.add_argument("--exclude-encrypted", "-X", action="store_true",
	help="Skip encrypted files, don't include them in the archives "
		"in any form.")

parser.add_argument("--decrypt-cmd", "-D", metavar="COMMAND",
	help=("Decrypt files with this command, %s by default."
		% ' '.join(DECRYPT_CMD)))
parser.add_argument("--decrypt-ext", "-x", metavar="EXTENSION",
	help="When decrypting a file, strip this extension "
		"from the file name (\"%s\" by default)." % DECRYPT_EXT)

parser.add_argument("top_level_dir", nargs='+', metavar="TOP-LEVEL-DIR",
	help="The directory hierarchy to make archives from.")

args = parser.parse_args()

if args.root_owner:
	# Make the files in the archives created by cpio(1) owned by root.
	CPIO.append("-R0:0")

if args.decrypt_cmd is not None:
	DECRYPT_CMD = shlex.split(args.decrypt_cmd)
if args.decrypt_ext is not None:
	DECRYPT_EXT = args.decrypt_ext

for top in args.top_level_dir:
	mkcpio(top, args)

# End of mkcpio.py
