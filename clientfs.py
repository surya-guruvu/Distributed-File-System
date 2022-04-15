#!/usr/bin/env python

from __future__ import with_statement

import grpc

import filesystem_pb2_grpc as pb2_grpc
import filesystem_pb2 as pb2

import os
import sys
import errno
import secure

from fuse import FUSE, FuseOSError, Operations, fuse_get_context

class dfs(Operations):
	def __init__(self,root):
		self.root=root;

	def _full_path(self, partial): 
		if partial.startswith("/"):
			partial = partial[1:]
		path = os.path.join(self.root, partial)
		return path

	def access(self, path, mode):
		full_path = self._full_path(path)		

		key = secure.loadServerPublicKey();
		path = bytes(full_path, 'utf-8')
		mode = mode.to_bytes(4,'big')

		encrypt_path = secure.encrypt(path,key)
		encrypt_mode = secure.encrypt(mode,key)	

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Access(pb2.AccessRequest(path=encrypt_path, mode=encrypt_mode))

			key1 = secure.loadClientPrivateKey()
			status = int.from_bytes(secure.decryption(response.status,key1),'big')

			if status!=0:
				raise FuseOSError(status);

	
	def getattr(self, path, fh=None):
		full_path = self._full_path(path)
		st = os.lstat(full_path)
		return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                     'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))




	def mkdir(self, path, mode):
		full_path = self._full_path(path)
		
		key = secure.loadServerPublicKey();
		path = bytes(full_path, 'utf-8')
		mode = mode.to_bytes(4,'big')

		encrypt_path = secure.encrypt(path,key)
		encrypt_mode = secure.encrypt(mode,key)
		
		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Mkdir(pb2.MkdirRequest(path=encrypt_path, mode=encrypt_mode))

			return None

	def rmdir(self, path):
		full_path = self._full_path(path)

		key = secure.loadServerPublicKey()
		path = bytes(full_path, 'utf-8')

		encrypt_path = secure.encrypt(path,key)
		
		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Rmdir(pb2.RmdirRequest(path=encrypt_path))

			return None

	def readdir(self, path, fh):
		full_path = self._full_path(path)

		key = secure.loadServerPublicKey()
		path = bytes(full_path, 'utf-8')

		key1 = secure.loadClientPrivateKey()

		encrypt_path = secure.encrypt(path,key)

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Readdir(pb2.ReaddirRequest(path=encrypt_path))

		for r in response.dirs:
			yield secure.decryption(r,key1).decode()


	def readlink(self, path):
		full_path = self._full_path(path)

		key = secure.loadServerPublicKey()
		path = bytes(full_path, 'utf-8')
		root = bytes(self.root, 'utf-8')


		encrypt_path = secure.encrypt(path,key)
		encrypt_root = secure.encrypt(root,key)


		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Readlink(pb2.ReadlinkRequest(path=encrypt_path,root=encrypt_root))

			key1 = secure.loadClientPrivateKey()

			pathname = secure.decryption(response.pathname,key1).decode()

			return pathname



	def mknod(self, path, mode, dev):
		full_path = self._full_path(path)
		
		key = secure.loadServerPublicKey();
		path = bytes(full_path, 'utf-8')
		mode = mode.to_bytes(4,'big')
		dev  = dev.to_bytes(4,'big')

		encrypt_path = secure.encrypt(path,key)
		encrypt_mode = secure.encrypt(mode,key)
		encrypt_dev = secure.encrypt(dev,key)

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Mknod(pb2.MknodRequest(path=encrypt_path,mode=encrypt_mode,dev=encrypt_dev))

			return None

	def chmod(self, path, mode):
		full_path = self._full_path(path)
		
		key = secure.loadServerPublicKey();
		path = bytes(full_path, 'utf-8')
		mode = mode.to_bytes(4,'big')

		encrypt_path = secure.encrypt(path,key)
		encrypt_mode = secure.encrypt(mode,key)

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Chmod(pb2.ChmodRequest(path=encrypt_path,mode=encrypt_mode))

			return None	
		


	def chown(self, path, uid, gid):
		full_path = self._full_path(path)
		
		key = secure.loadServerPublicKey();

		path = bytes(full_path, 'utf-8')
		uid = uid.to_bytes(4,'big')
		gid = gid.to_bytes(4,'big')


		encrypt_path = secure.encrypt(path,key)
		encrypt_gid = secure.encrypt(gid,key)
		encrypt_uid = secure.encrypt(uid,key)


		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Chown(pb2.ChownRequest(path=encrypt_path,uid=encrypt_uid,gid=encrypt_gid))

			return None

	def statfs(self, path):
		full_path = self._full_path(path)
		stv = os.statvfs(full_path)
		return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

	def unlink(self, path):
		full_path = self._full_path(path)
		
		key = secure.loadServerPublicKey();
		path = bytes(full_path, 'utf-8')

		encrypt_path = secure.encrypt(path,key)


		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Unlink(pb2.UnlinkRequest(path=encrypt_path))

			return None

	def symlink(self, name, target):
		return os.symlink(target, self._full_path(name))

	def rename(self, old, new):
		old1 = self._full_path(old)
		new1 = self._full_path(new)

		key = secure.loadServerPublicKey()
		old1 = bytes(old1, 'utf-8')
		new1 = bytes(new1, 'utf-8')

		old1 = secure.encrypt(old1,key)
		new1 = secure.encrypt(new1,key)

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Rename(pb2.RenameRequest(old=old1,new=new1))

			return None

	def link(self, target, name):
		name1 = self._full_path(name)
		target1 = self._full_path(target)

		key = secure.loadServerPublicKey()
		name1 = bytes(name1, 'utf-8')
		target1 = bytes(target1, 'utf-8')

		name1 = secure.encrypt(name1,key)
		target1 = secure.encrypt(target1,key)

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Link(pb2.LinkRequest(name=name1,target=target1))

			return None
		

	def utimens(self, path, times=None):
		full_path = self._full_path(path)
		atime = times[0]
		mtime = times[1]
		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Utime(pb2.UtimeRequest(path=full_path,atime=atime,mtime=mtime))

			return None
		

    # File methods
    # ============

	def open(self, path, flags):
		full_path = self._full_path(path)
		
		key = secure.loadServerPublicKey();
		path = bytes(full_path, 'utf-8')
		flags = flags.to_bytes(4,'big')

		encrypt_path = secure.encrypt(path,key)
		encrypt_flags = secure.encrypt(flags,key)

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Open(pb2.OpenRequest(path=encrypt_path ,flags=encrypt_flags))

			key1 = secure.loadClientPrivateKey()
			fd = int.from_bytes(secure.decryption(response.fd,key1),'big')

			return (fd)

	def create(self, path, mode, fi=None):
		uid, gid, pid = fuse_get_context()
		full_path = self._full_path(path)

		key = secure.loadServerPublicKey();
		path = bytes(full_path, 'utf-8')
		mode = mode.to_bytes(4,'big')

		uid = uid.to_bytes(4,'big')
		gid = gid.to_bytes(4,'big')
		pid = pid.to_bytes(4,'big')

		encrypt_path = secure.encrypt(path,key)
		encrypt_mode = secure.encrypt(mode,key)

		encrypt_gid = secure.encrypt(gid,key)
		encrypt_uid = secure.encrypt(uid,key)
		encrypt_pid = secure.encrypt(pid,key)

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Create(pb2.CreateRequest(path=encrypt_path,uid=encrypt_uid,gid=encrypt_gid,pid=encrypt_pid,mode=encrypt_mode))

			key1 = secure.loadClientPrivateKey()
			fd = int.from_bytes(secure.decryption(response.fd,key1),'big')

			return (fd)
		

	def read(self, path, length, offset, fh):
		full_path = self._full_path(path)

		key = secure.loadServerPublicKey();
		path = bytes(full_path, 'utf-8')
		length = length.to_bytes(4,'big')
		offset = offset.to_bytes(4,'big')
		fh = fh.to_bytes(4,'big')

		encrypt_path = secure.encrypt(path,key)
		encrypt_length = secure.encrypt(length,key)
		encrypt_offset = secure.encrypt(offset,key)
		encrypt_fh = secure.encrypt(fh,key)


		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Read(pb2.ReadRequest(path=encrypt_path,size=encrypt_length,offset=encrypt_offset,fileHandle=encrypt_fh))
			
			key1 = secure.loadClientPrivateKey()
			data = secure.decryption(response.data,key1)
			print(data)
			
			return (data)

	def write(self, path, buf, offset, fh):
		full_path = self._full_path(path)

		key = secure.loadServerPublicKey();
		path = bytes(full_path, 'utf-8')
		offset = offset.to_bytes(4,'big')
		fh = fh.to_bytes(4,'big')

		encrypt_path = secure.encrypt(path,key)
		encrypt_offset = secure.encrypt(offset,key)
		encrypt_fh = secure.encrypt(fh,key)
		encrypt_buffer = secure.encrypt(buf,key)

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Write(pb2.WriteRequest(path=encrypt_path,buffer=encrypt_buffer,offset=encrypt_offset,fileHandle=encrypt_fh))

			key1 = secure.loadClientPrivateKey()
			numBytes = int.from_bytes(secure.decryption(response.numBytes,key1),'big')

			return numBytes

	def truncate(self, path, length, fh=None):
		full_path = self._full_path(path)

		key = secure.loadServerPublicKey();
		path = bytes(full_path, 'utf-8')
		length = length.to_bytes(4,'big')

		encrypt_path = secure.encrypt(path,key)
		encrypt_length = secure.encrypt(length,key)

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Truncate(pb2.TruncateRequest(path=encrypt_path,size=encrypt_length))


	def flush(self, path, fh):
		key = secure.loadServerPublicKey()
		fh = fh.to_bytes(4,'big')
		encrypt_fh = secure.encrypt(fh,key)

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Flush(pb2.FlushRequest(fd=encrypt_fh))

			return None
		

	def release(self, path, fh):
		key = secure.loadServerPublicKey()
		fh = fh.to_bytes(4,'big')
		encrypt_fh = secure.encrypt(fh,key)

		with grpc.insecure_channel('localhost:50051') as channel:
			stub = pb2_grpc.FileSystemStub(channel)
			response = stub.Close(pb2.CloseRequest(fd=encrypt_fh))

			return None

	def fsync(self, path, fdatasync, fh):
		return self.flush(path, fh)


def main(mountpoint, root):
    FUSE(dfs(root), mountpoint, nothreads=True, foreground=True, allow_other=True)


if __name__ == '__main__':
	secure.genClientKeys()
	main(sys.argv[2], sys.argv[1])

			
