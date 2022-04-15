import grpc
from concurrent import futures
import time
import filesystem_pb2_grpc as pb2_grpc
import filesystem_pb2 as pb2

import os
import sys
import errno
import secure


class FileSystem(pb2_grpc.FileSystemServicer):
 
	def sendStringRequest(self, request, context): 
		a=request.original
		n=len(a);
		return pb2.StringReply(reversed = a[::-1]);

	def Access(self,request,context):
		key = secure.loadServerPrivateKey();
		path = secure.decryption(request.path,key).decode()
		mode = int.from_bytes(secure.decryption(request.mode,key),'big')

		print("Access request Done")

		if not os.access(path, mode):
			status = errno.EACCES
			
		else:
			status = 0

		status = status.to_bytes(4,'big')
		key1 = secure.loadClientPublicKey();
		encrypt_status = secure.encrypt(status,key1)	
		return pb2.AccessReply(status = encrypt_status)

	def Mkdir(self,request,context):
		key = secure.loadServerPrivateKey();
		path = secure.decryption(request.path,key).decode()
		mode = int.from_bytes(secure.decryption(request.mode,key),'big')
		
		print("Mkdir request Done")

		#returncode= os.mkdir(path, mode)
		os.mkdir(path,mode)
		
		return pb2.MkdirReply(status = 0)

	def Rmdir(self,request,context):
		key = secure.loadServerPrivateKey();
		path = secure.decryption(request.path,key).decode()

		print("Rmdir request Done")

		os.rmdir(path)

		return pb2.RmdirReply(status = 0)

	def Readdir(self,request,context):
		key = secure.loadServerPrivateKey();
		path = secure.decryption(request.path,key).decode()

		key1 = secure.loadClientPublicKey();

		dirents = ['.', '..']
		if os.path.isdir(path):
			dirents.extend(os.listdir(path))

		for i in range(len(dirents)):
			path = bytes(dirents[i], 'utf-8')

			encrypt_path = secure.encrypt(path,key1)
			dirents[i] = encrypt_path


		dir1 = pb2.ReaddirReply()
		dir1.dirs.extend(dirents)
		
		print("Readdir request Done")

		return dir1

	def GetAttr(self,request,context):

		path = request.path

		st = os.lstat(path)

		print("GetAttr request Done")

		return pb2.GetAttrReply(atime = (getattr(st,'st_atime')),
			ctime=getattr(st,'st_ctime'),
			gid=getattr(st,'st_gid'),
			mode=getattr(st,'st_mode'),
			mtime=getattr(st,'st_mtime'),
			nlink=int(getattr(st,'st_nlink')),
			size=getattr(st,'st_size'),
			uid=getattr(st,'st_uid'))

	def Open(self,request,context):
		key = secure.loadServerPrivateKey();
		path = secure.decryption(request.path,key).decode()
		flags = int.from_bytes(secure.decryption(request.flags,key),'big')	

		print("Open request Done")

		fd=os.open(path, flags)

		fd = fd.to_bytes(4,'big')
		key1 = secure.loadClientPublicKey();
		encrypt_fd = secure.encrypt(fd,key1)	

		return pb2.OpenReply(fd = encrypt_fd)
		
	def Read(self,request,context):
		key = secure.loadServerPrivateKey();
		path   = secure.decryption(request.path,key).decode()
		size   = int.from_bytes(secure.decryption(request.size,key),'big')
		offset = int.from_bytes(secure.decryption(request.offset,key),'big')
		fh     = int.from_bytes(secure.decryption(request.fileHandle,key),'big')
		
		os.lseek(fh, offset, os.SEEK_SET)
		
		print("Read request Done")

		data=os.read(fh, size)
		key1 = secure.loadClientPublicKey();
		encrypt_data = secure.encrypt(data,key1)
		
		return pb2.ReadReply(data = encrypt_data)

	def Write(self,request,context):
		key = secure.loadServerPrivateKey();
		path   = secure.decryption(request.path,key).decode()
		buf   =  secure.decryption(request.buffer,key)
		offset = int.from_bytes(secure.decryption(request.offset,key),'big')
		fh     = int.from_bytes(secure.decryption(request.fileHandle,key),'big')

		os.lseek(fh, offset, os.SEEK_SET)

		print("Write request Done")

		numBytes=os.write(fh,buf)
		key1 = secure.loadClientPublicKey();
		numBytes = numBytes.to_bytes(4,'big')

		encrypt_numBytes = secure.encrypt(numBytes,key1)

		return pb2.WriteReply(numBytes = encrypt_numBytes)

	def Truncate(self,request,context):
		key = secure.loadServerPrivateKey();
		path   = secure.decryption(request.path,key).decode()
		size   = int.from_bytes(secure.decryption(request.size,key),'big')

		with open(path, 'r+') as f:
			f.truncate(size)
		print("Truncate request Done")

		return pb2.TruncateReply(status=1)

	def Chown(self,request,context):
		key = secure.loadServerPrivateKey();
		path = secure.decryption(request.path,key).decode()
		uid = int.from_bytes(secure.decryption(request.uid,key),'big')
		gid = int.from_bytes(secure.decryption(request.gid,key),'big')

		os.chown(path, uid, gid)

		print("Chown request Done")

		return pb2.ChownReply(status=1)

	def Create(self,request,context):
		key = secure.loadServerPrivateKey();
		path = secure.decryption(request.path,key).decode()
		mode = int.from_bytes(secure.decryption(request.mode,key),'big')
		uid = int.from_bytes(secure.decryption(request.uid,key),'big')
		pid = int.from_bytes(secure.decryption(request.pid,key),'big')
		gid = int.from_bytes(secure.decryption(request.gid,key),'big')


		fd = os.open(path, os.O_WRONLY | os.O_CREAT, mode)
		os.chown(path,uid,gid) #chown to context uid & gid

		fd = fd.to_bytes(4,'big')
		key1 = secure.loadClientPublicKey();
		encrypt_fd = secure.encrypt(fd,key1)

		print("Create request Done")

		return pb2.CreateReply(fd=encrypt_fd)

	def Flush(self,request,context):
		key = secure.loadServerPrivateKey();
		fh     = int.from_bytes(secure.decryption(request.fd,key),'big')
		os.fsync(fh)

		print("Flush request Done")

		return pb2.FlushReply(status=1)

	def Close(self,request,context):
		key = secure.loadServerPrivateKey();
		fh     = int.from_bytes(secure.decryption(request.fd,key),'big')
		os.close(fh)

		print("Close request Done")

		return pb2.CloseReply(status=1)

	def Mknod(self,request,context):
		key = secure.loadServerPrivateKey();
		path = secure.decryption(request.path,key).decode()
		mode = int.from_bytes(secure.decryption(request.mode,key),'big')
		dev  = int.from_bytes(secure.decryption(request.dev,key),'big')

		os.mknod(path, mode, dev)

		print("Mknod request Done")

		return pb2.MknodReply(status=1)

	def Chmod(self,request,context):
		key = secure.loadServerPrivateKey();
		path = secure.decryption(request.path,key).decode()
		mode = int.from_bytes(secure.decryption(request.mode,key),'big')

		os.chmod(path,mode)

		print("Chmod Request Done")

		return pb2.ChmodReply(status=1)

	def Unlink(self,request,context):
		key = secure.loadServerPrivateKey();
		path = secure.decryption(request.path,key).decode()

		os.unlink(path)

		print("Unlink Request Done")

		return pb2.UnlinkReply(status=1)

	def Rename(self,request,context):
		key = secure.loadServerPrivateKey();
		old = secure.decryption(request.old,key).decode()
		new = secure.decryption(request.new,key).decode()

		os.rename(old,new)

		print("Rename Request Done")

		return pb2.RenameReply(status=1)

	def Link(self,request,context):
		key = secure.loadServerPrivateKey();
		name = secure.decryption(request.name,key).decode()
		target = secure.decryption(request.target,key).decode()

		os.link(name, target)

		print("Link Request Done")

		return pb2.LinkReply(status=1)

	def Utime(self,request,context):
		path=request.path
		mtime=request.mtime
		atime=request.atime

		times = (atime,mtime)

		os.utime(path, times)

		print("Utime Request Done")

		return pb2.UtimeReply(status=1)

	def Readlink(self,request,context):
		key = secure.loadServerPrivateKey();
		path = secure.decryption(request.path,key).decode()
		root = secure.decryption(request.root,key).decode()

		pathname = os.readlink(path)
		if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
			req = os.path.relpath(pathname, root)
		else:	
			req = pathname

		key1 = secure.loadClientPublicKey();
		pathname = bytes(req, 'utf-8')
		encrypt_path = secure.encrypt(pathname,key)

		return pb2.ReadlinkReply(pathname =encrypt_path)


		
def server():
	secure.genServerKeys()
	server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
	pb2_grpc.add_FileSystemServicer_to_server(FileSystem(), server)
	server.add_insecure_port('[::]:50051')
	print("gRPC starting")
	server.start()
	server.wait_for_termination()
   	
server();
	
