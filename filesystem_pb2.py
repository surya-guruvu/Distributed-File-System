# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: filesystem.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10\x66ilesystem.proto\x12\nfilesystem\"!\n\rStringRequest\x12\x10\n\x08original\x18\x01 \x01(\t\"\x1f\n\x0bStringReply\x12\x10\n\x08reversed\x18\x01 \x01(\t\"+\n\rAccessRequest\x12\x0c\n\x04path\x18\x01 \x01(\x0c\x12\x0c\n\x04mode\x18\x02 \x01(\x0c\"\x1d\n\x0b\x41\x63\x63\x65ssReply\x12\x0e\n\x06status\x18\x01 \x01(\x0c\"*\n\x0cMkdirRequest\x12\x0c\n\x04path\x18\x01 \x01(\x0c\x12\x0c\n\x04mode\x18\x02 \x01(\x0c\"\x1c\n\nMkdirReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\"\x1c\n\x0cRmdirRequest\x12\x0c\n\x04path\x18\x01 \x01(\x0c\"\x1c\n\nRmdirReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\"\x1e\n\x0eReaddirRequest\x12\x0c\n\x04path\x18\x01 \x01(\x0c\"\x1c\n\x0cReaddirReply\x12\x0c\n\x04\x64irs\x18\x01 \x03(\x0c\"\x1e\n\x0eGetAttrRequest\x12\x0c\n\x04path\x18\x01 \x01(\t\"\x80\x01\n\x0cGetAttrReply\x12\r\n\x05\x61time\x18\x01 \x01(\x02\x12\r\n\x05\x63time\x18\x02 \x01(\x02\x12\x0b\n\x03gid\x18\x03 \x01(\r\x12\x0c\n\x04mode\x18\x04 \x01(\x04\x12\r\n\x05mtime\x18\x05 \x01(\x02\x12\r\n\x05nlink\x18\x06 \x01(\x04\x12\x0c\n\x04size\x18\x07 \x01(\x04\x12\x0b\n\x03uid\x18\x08 \x01(\r\"*\n\x0bOpenRequest\x12\x0c\n\x04path\x18\x01 \x01(\x0c\x12\r\n\x05\x66lags\x18\x02 \x01(\x0c\"\x17\n\tOpenReply\x12\n\n\x02\x66\x64\x18\x01 \x01(\x0c\"M\n\x0bReadRequest\x12\x12\n\nfileHandle\x18\x01 \x01(\x0c\x12\x0c\n\x04size\x18\x02 \x01(\x0c\x12\x0e\n\x06offset\x18\x03 \x01(\x0c\x12\x0c\n\x04path\x18\x04 \x01(\x0c\"\x19\n\tReadReply\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\x0c\"P\n\x0cWriteRequest\x12\x12\n\nfileHandle\x18\x01 \x01(\x0c\x12\x0e\n\x06\x62uffer\x18\x02 \x01(\x0c\x12\x0e\n\x06offset\x18\x03 \x01(\x0c\x12\x0c\n\x04path\x18\x04 \x01(\x0c\"\x1e\n\nWriteReply\x12\x10\n\x08numBytes\x18\x01 \x01(\x0c\"-\n\x0fTruncateRequest\x12\x0c\n\x04path\x18\x01 \x01(\x0c\x12\x0c\n\x04size\x18\x02 \x01(\x0c\"\x1f\n\rTruncateReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\"6\n\x0c\x43hownRequest\x12\x0b\n\x03uid\x18\x01 \x01(\x0c\x12\x0b\n\x03gid\x18\x02 \x01(\x0c\x12\x0c\n\x04path\x18\x03 \x01(\x0c\"\x1c\n\nChownReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\"R\n\rCreateRequest\x12\x0b\n\x03uid\x18\x01 \x01(\x0c\x12\x0b\n\x03gid\x18\x02 \x01(\x0c\x12\x0c\n\x04path\x18\x03 \x01(\x0c\x12\x0b\n\x03pid\x18\x04 \x01(\x0c\x12\x0c\n\x04mode\x18\x05 \x01(\x0c\"\x19\n\x0b\x43reateReply\x12\n\n\x02\x66\x64\x18\x01 \x01(\x0c\"\x1a\n\x0c\x46lushRequest\x12\n\n\x02\x66\x64\x18\x01 \x01(\x0c\"\x1c\n\nFlushReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\"\x1a\n\x0c\x43loseRequest\x12\n\n\x02\x66\x64\x18\x01 \x01(\x0c\"\x1c\n\nCloseReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\"7\n\x0cMknodRequest\x12\x0c\n\x04path\x18\x01 \x01(\x0c\x12\x0c\n\x04mode\x18\x02 \x01(\x0c\x12\x0b\n\x03\x64\x65v\x18\x03 \x01(\x0c\"\x1c\n\nMknodReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\"*\n\x0c\x43hmodRequest\x12\x0c\n\x04path\x18\x01 \x01(\x0c\x12\x0c\n\x04mode\x18\x02 \x01(\x0c\"\x1c\n\nChmodReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\"\x1d\n\rUnlinkRequest\x12\x0c\n\x04path\x18\x01 \x01(\x0c\"\x1d\n\x0bUnlinkReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\")\n\rRenameRequest\x12\x0b\n\x03old\x18\x01 \x01(\x0c\x12\x0b\n\x03new\x18\x02 \x01(\x0c\"\x1d\n\x0bRenameReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\"+\n\x0bLinkRequest\x12\x0c\n\x04name\x18\x01 \x01(\x0c\x12\x0e\n\x06target\x18\x02 \x01(\x0c\"\x1b\n\tLinkReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\":\n\x0cUtimeRequest\x12\x0c\n\x04path\x18\x01 \x01(\t\x12\r\n\x05\x61time\x18\x02 \x01(\x02\x12\r\n\x05mtime\x18\x03 \x01(\x02\"\x1c\n\nUtimeReply\x12\x0e\n\x06status\x18\x01 \x01(\x05\"-\n\x0fReadlinkRequest\x12\x0c\n\x04path\x18\x01 \x01(\x0c\x12\x0c\n\x04root\x18\x02 \x01(\x0c\"!\n\rReadlinkReply\x12\x10\n\x08pathname\x18\x01 \x01(\x0c\x32\xbc\n\n\nFileSystem\x12I\n\x11sendStringRequest\x12\x19.filesystem.StringRequest\x1a\x17.filesystem.StringReply\"\x00\x12>\n\x06\x41\x63\x63\x65ss\x12\x19.filesystem.AccessRequest\x1a\x17.filesystem.AccessReply\"\x00\x12;\n\x05Mkdir\x12\x18.filesystem.MkdirRequest\x1a\x16.filesystem.MkdirReply\"\x00\x12;\n\x05Rmdir\x12\x18.filesystem.RmdirRequest\x1a\x16.filesystem.RmdirReply\"\x00\x12\x41\n\x07Readdir\x12\x1a.filesystem.ReaddirRequest\x1a\x18.filesystem.ReaddirReply\"\x00\x12\x41\n\x07GetAttr\x12\x1a.filesystem.GetAttrRequest\x1a\x18.filesystem.GetAttrReply\"\x00\x12\x38\n\x04Open\x12\x17.filesystem.OpenRequest\x1a\x15.filesystem.OpenReply\"\x00\x12\x38\n\x04Read\x12\x17.filesystem.ReadRequest\x1a\x15.filesystem.ReadReply\"\x00\x12;\n\x05Write\x12\x18.filesystem.WriteRequest\x1a\x16.filesystem.WriteReply\"\x00\x12\x44\n\x08Truncate\x12\x1b.filesystem.TruncateRequest\x1a\x19.filesystem.TruncateReply\"\x00\x12;\n\x05\x43hown\x12\x18.filesystem.ChownRequest\x1a\x16.filesystem.ChownReply\"\x00\x12>\n\x06\x43reate\x12\x19.filesystem.CreateRequest\x1a\x17.filesystem.CreateReply\"\x00\x12;\n\x05\x46lush\x12\x18.filesystem.FlushRequest\x1a\x16.filesystem.FlushReply\"\x00\x12;\n\x05\x43lose\x12\x18.filesystem.CloseRequest\x1a\x16.filesystem.CloseReply\"\x00\x12;\n\x05Mknod\x12\x18.filesystem.MknodRequest\x1a\x16.filesystem.MknodReply\"\x00\x12;\n\x05\x43hmod\x12\x18.filesystem.ChmodRequest\x1a\x16.filesystem.ChmodReply\"\x00\x12>\n\x06Unlink\x12\x19.filesystem.UnlinkRequest\x1a\x17.filesystem.UnlinkReply\"\x00\x12>\n\x06Rename\x12\x19.filesystem.RenameRequest\x1a\x17.filesystem.RenameReply\"\x00\x12\x38\n\x04Link\x12\x17.filesystem.LinkRequest\x1a\x15.filesystem.LinkReply\"\x00\x12;\n\x05Utime\x12\x18.filesystem.UtimeRequest\x1a\x16.filesystem.UtimeReply\"\x00\x12\x44\n\x08Readlink\x12\x1b.filesystem.ReadlinkRequest\x1a\x19.filesystem.ReadlinkReply\"\x00\x62\x06proto3')



_STRINGREQUEST = DESCRIPTOR.message_types_by_name['StringRequest']
_STRINGREPLY = DESCRIPTOR.message_types_by_name['StringReply']
_ACCESSREQUEST = DESCRIPTOR.message_types_by_name['AccessRequest']
_ACCESSREPLY = DESCRIPTOR.message_types_by_name['AccessReply']
_MKDIRREQUEST = DESCRIPTOR.message_types_by_name['MkdirRequest']
_MKDIRREPLY = DESCRIPTOR.message_types_by_name['MkdirReply']
_RMDIRREQUEST = DESCRIPTOR.message_types_by_name['RmdirRequest']
_RMDIRREPLY = DESCRIPTOR.message_types_by_name['RmdirReply']
_READDIRREQUEST = DESCRIPTOR.message_types_by_name['ReaddirRequest']
_READDIRREPLY = DESCRIPTOR.message_types_by_name['ReaddirReply']
_GETATTRREQUEST = DESCRIPTOR.message_types_by_name['GetAttrRequest']
_GETATTRREPLY = DESCRIPTOR.message_types_by_name['GetAttrReply']
_OPENREQUEST = DESCRIPTOR.message_types_by_name['OpenRequest']
_OPENREPLY = DESCRIPTOR.message_types_by_name['OpenReply']
_READREQUEST = DESCRIPTOR.message_types_by_name['ReadRequest']
_READREPLY = DESCRIPTOR.message_types_by_name['ReadReply']
_WRITEREQUEST = DESCRIPTOR.message_types_by_name['WriteRequest']
_WRITEREPLY = DESCRIPTOR.message_types_by_name['WriteReply']
_TRUNCATEREQUEST = DESCRIPTOR.message_types_by_name['TruncateRequest']
_TRUNCATEREPLY = DESCRIPTOR.message_types_by_name['TruncateReply']
_CHOWNREQUEST = DESCRIPTOR.message_types_by_name['ChownRequest']
_CHOWNREPLY = DESCRIPTOR.message_types_by_name['ChownReply']
_CREATEREQUEST = DESCRIPTOR.message_types_by_name['CreateRequest']
_CREATEREPLY = DESCRIPTOR.message_types_by_name['CreateReply']
_FLUSHREQUEST = DESCRIPTOR.message_types_by_name['FlushRequest']
_FLUSHREPLY = DESCRIPTOR.message_types_by_name['FlushReply']
_CLOSEREQUEST = DESCRIPTOR.message_types_by_name['CloseRequest']
_CLOSEREPLY = DESCRIPTOR.message_types_by_name['CloseReply']
_MKNODREQUEST = DESCRIPTOR.message_types_by_name['MknodRequest']
_MKNODREPLY = DESCRIPTOR.message_types_by_name['MknodReply']
_CHMODREQUEST = DESCRIPTOR.message_types_by_name['ChmodRequest']
_CHMODREPLY = DESCRIPTOR.message_types_by_name['ChmodReply']
_UNLINKREQUEST = DESCRIPTOR.message_types_by_name['UnlinkRequest']
_UNLINKREPLY = DESCRIPTOR.message_types_by_name['UnlinkReply']
_RENAMEREQUEST = DESCRIPTOR.message_types_by_name['RenameRequest']
_RENAMEREPLY = DESCRIPTOR.message_types_by_name['RenameReply']
_LINKREQUEST = DESCRIPTOR.message_types_by_name['LinkRequest']
_LINKREPLY = DESCRIPTOR.message_types_by_name['LinkReply']
_UTIMEREQUEST = DESCRIPTOR.message_types_by_name['UtimeRequest']
_UTIMEREPLY = DESCRIPTOR.message_types_by_name['UtimeReply']
_READLINKREQUEST = DESCRIPTOR.message_types_by_name['ReadlinkRequest']
_READLINKREPLY = DESCRIPTOR.message_types_by_name['ReadlinkReply']
StringRequest = _reflection.GeneratedProtocolMessageType('StringRequest', (_message.Message,), {
  'DESCRIPTOR' : _STRINGREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.StringRequest)
  })
_sym_db.RegisterMessage(StringRequest)

StringReply = _reflection.GeneratedProtocolMessageType('StringReply', (_message.Message,), {
  'DESCRIPTOR' : _STRINGREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.StringReply)
  })
_sym_db.RegisterMessage(StringReply)

AccessRequest = _reflection.GeneratedProtocolMessageType('AccessRequest', (_message.Message,), {
  'DESCRIPTOR' : _ACCESSREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.AccessRequest)
  })
_sym_db.RegisterMessage(AccessRequest)

AccessReply = _reflection.GeneratedProtocolMessageType('AccessReply', (_message.Message,), {
  'DESCRIPTOR' : _ACCESSREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.AccessReply)
  })
_sym_db.RegisterMessage(AccessReply)

MkdirRequest = _reflection.GeneratedProtocolMessageType('MkdirRequest', (_message.Message,), {
  'DESCRIPTOR' : _MKDIRREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.MkdirRequest)
  })
_sym_db.RegisterMessage(MkdirRequest)

MkdirReply = _reflection.GeneratedProtocolMessageType('MkdirReply', (_message.Message,), {
  'DESCRIPTOR' : _MKDIRREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.MkdirReply)
  })
_sym_db.RegisterMessage(MkdirReply)

RmdirRequest = _reflection.GeneratedProtocolMessageType('RmdirRequest', (_message.Message,), {
  'DESCRIPTOR' : _RMDIRREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.RmdirRequest)
  })
_sym_db.RegisterMessage(RmdirRequest)

RmdirReply = _reflection.GeneratedProtocolMessageType('RmdirReply', (_message.Message,), {
  'DESCRIPTOR' : _RMDIRREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.RmdirReply)
  })
_sym_db.RegisterMessage(RmdirReply)

ReaddirRequest = _reflection.GeneratedProtocolMessageType('ReaddirRequest', (_message.Message,), {
  'DESCRIPTOR' : _READDIRREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.ReaddirRequest)
  })
_sym_db.RegisterMessage(ReaddirRequest)

ReaddirReply = _reflection.GeneratedProtocolMessageType('ReaddirReply', (_message.Message,), {
  'DESCRIPTOR' : _READDIRREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.ReaddirReply)
  })
_sym_db.RegisterMessage(ReaddirReply)

GetAttrRequest = _reflection.GeneratedProtocolMessageType('GetAttrRequest', (_message.Message,), {
  'DESCRIPTOR' : _GETATTRREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.GetAttrRequest)
  })
_sym_db.RegisterMessage(GetAttrRequest)

GetAttrReply = _reflection.GeneratedProtocolMessageType('GetAttrReply', (_message.Message,), {
  'DESCRIPTOR' : _GETATTRREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.GetAttrReply)
  })
_sym_db.RegisterMessage(GetAttrReply)

OpenRequest = _reflection.GeneratedProtocolMessageType('OpenRequest', (_message.Message,), {
  'DESCRIPTOR' : _OPENREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.OpenRequest)
  })
_sym_db.RegisterMessage(OpenRequest)

OpenReply = _reflection.GeneratedProtocolMessageType('OpenReply', (_message.Message,), {
  'DESCRIPTOR' : _OPENREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.OpenReply)
  })
_sym_db.RegisterMessage(OpenReply)

ReadRequest = _reflection.GeneratedProtocolMessageType('ReadRequest', (_message.Message,), {
  'DESCRIPTOR' : _READREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.ReadRequest)
  })
_sym_db.RegisterMessage(ReadRequest)

ReadReply = _reflection.GeneratedProtocolMessageType('ReadReply', (_message.Message,), {
  'DESCRIPTOR' : _READREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.ReadReply)
  })
_sym_db.RegisterMessage(ReadReply)

WriteRequest = _reflection.GeneratedProtocolMessageType('WriteRequest', (_message.Message,), {
  'DESCRIPTOR' : _WRITEREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.WriteRequest)
  })
_sym_db.RegisterMessage(WriteRequest)

WriteReply = _reflection.GeneratedProtocolMessageType('WriteReply', (_message.Message,), {
  'DESCRIPTOR' : _WRITEREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.WriteReply)
  })
_sym_db.RegisterMessage(WriteReply)

TruncateRequest = _reflection.GeneratedProtocolMessageType('TruncateRequest', (_message.Message,), {
  'DESCRIPTOR' : _TRUNCATEREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.TruncateRequest)
  })
_sym_db.RegisterMessage(TruncateRequest)

TruncateReply = _reflection.GeneratedProtocolMessageType('TruncateReply', (_message.Message,), {
  'DESCRIPTOR' : _TRUNCATEREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.TruncateReply)
  })
_sym_db.RegisterMessage(TruncateReply)

ChownRequest = _reflection.GeneratedProtocolMessageType('ChownRequest', (_message.Message,), {
  'DESCRIPTOR' : _CHOWNREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.ChownRequest)
  })
_sym_db.RegisterMessage(ChownRequest)

ChownReply = _reflection.GeneratedProtocolMessageType('ChownReply', (_message.Message,), {
  'DESCRIPTOR' : _CHOWNREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.ChownReply)
  })
_sym_db.RegisterMessage(ChownReply)

CreateRequest = _reflection.GeneratedProtocolMessageType('CreateRequest', (_message.Message,), {
  'DESCRIPTOR' : _CREATEREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.CreateRequest)
  })
_sym_db.RegisterMessage(CreateRequest)

CreateReply = _reflection.GeneratedProtocolMessageType('CreateReply', (_message.Message,), {
  'DESCRIPTOR' : _CREATEREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.CreateReply)
  })
_sym_db.RegisterMessage(CreateReply)

FlushRequest = _reflection.GeneratedProtocolMessageType('FlushRequest', (_message.Message,), {
  'DESCRIPTOR' : _FLUSHREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.FlushRequest)
  })
_sym_db.RegisterMessage(FlushRequest)

FlushReply = _reflection.GeneratedProtocolMessageType('FlushReply', (_message.Message,), {
  'DESCRIPTOR' : _FLUSHREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.FlushReply)
  })
_sym_db.RegisterMessage(FlushReply)

CloseRequest = _reflection.GeneratedProtocolMessageType('CloseRequest', (_message.Message,), {
  'DESCRIPTOR' : _CLOSEREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.CloseRequest)
  })
_sym_db.RegisterMessage(CloseRequest)

CloseReply = _reflection.GeneratedProtocolMessageType('CloseReply', (_message.Message,), {
  'DESCRIPTOR' : _CLOSEREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.CloseReply)
  })
_sym_db.RegisterMessage(CloseReply)

MknodRequest = _reflection.GeneratedProtocolMessageType('MknodRequest', (_message.Message,), {
  'DESCRIPTOR' : _MKNODREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.MknodRequest)
  })
_sym_db.RegisterMessage(MknodRequest)

MknodReply = _reflection.GeneratedProtocolMessageType('MknodReply', (_message.Message,), {
  'DESCRIPTOR' : _MKNODREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.MknodReply)
  })
_sym_db.RegisterMessage(MknodReply)

ChmodRequest = _reflection.GeneratedProtocolMessageType('ChmodRequest', (_message.Message,), {
  'DESCRIPTOR' : _CHMODREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.ChmodRequest)
  })
_sym_db.RegisterMessage(ChmodRequest)

ChmodReply = _reflection.GeneratedProtocolMessageType('ChmodReply', (_message.Message,), {
  'DESCRIPTOR' : _CHMODREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.ChmodReply)
  })
_sym_db.RegisterMessage(ChmodReply)

UnlinkRequest = _reflection.GeneratedProtocolMessageType('UnlinkRequest', (_message.Message,), {
  'DESCRIPTOR' : _UNLINKREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.UnlinkRequest)
  })
_sym_db.RegisterMessage(UnlinkRequest)

UnlinkReply = _reflection.GeneratedProtocolMessageType('UnlinkReply', (_message.Message,), {
  'DESCRIPTOR' : _UNLINKREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.UnlinkReply)
  })
_sym_db.RegisterMessage(UnlinkReply)

RenameRequest = _reflection.GeneratedProtocolMessageType('RenameRequest', (_message.Message,), {
  'DESCRIPTOR' : _RENAMEREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.RenameRequest)
  })
_sym_db.RegisterMessage(RenameRequest)

RenameReply = _reflection.GeneratedProtocolMessageType('RenameReply', (_message.Message,), {
  'DESCRIPTOR' : _RENAMEREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.RenameReply)
  })
_sym_db.RegisterMessage(RenameReply)

LinkRequest = _reflection.GeneratedProtocolMessageType('LinkRequest', (_message.Message,), {
  'DESCRIPTOR' : _LINKREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.LinkRequest)
  })
_sym_db.RegisterMessage(LinkRequest)

LinkReply = _reflection.GeneratedProtocolMessageType('LinkReply', (_message.Message,), {
  'DESCRIPTOR' : _LINKREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.LinkReply)
  })
_sym_db.RegisterMessage(LinkReply)

UtimeRequest = _reflection.GeneratedProtocolMessageType('UtimeRequest', (_message.Message,), {
  'DESCRIPTOR' : _UTIMEREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.UtimeRequest)
  })
_sym_db.RegisterMessage(UtimeRequest)

UtimeReply = _reflection.GeneratedProtocolMessageType('UtimeReply', (_message.Message,), {
  'DESCRIPTOR' : _UTIMEREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.UtimeReply)
  })
_sym_db.RegisterMessage(UtimeReply)

ReadlinkRequest = _reflection.GeneratedProtocolMessageType('ReadlinkRequest', (_message.Message,), {
  'DESCRIPTOR' : _READLINKREQUEST,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.ReadlinkRequest)
  })
_sym_db.RegisterMessage(ReadlinkRequest)

ReadlinkReply = _reflection.GeneratedProtocolMessageType('ReadlinkReply', (_message.Message,), {
  'DESCRIPTOR' : _READLINKREPLY,
  '__module__' : 'filesystem_pb2'
  # @@protoc_insertion_point(class_scope:filesystem.ReadlinkReply)
  })
_sym_db.RegisterMessage(ReadlinkReply)

_FILESYSTEM = DESCRIPTOR.services_by_name['FileSystem']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _STRINGREQUEST._serialized_start=32
  _STRINGREQUEST._serialized_end=65
  _STRINGREPLY._serialized_start=67
  _STRINGREPLY._serialized_end=98
  _ACCESSREQUEST._serialized_start=100
  _ACCESSREQUEST._serialized_end=143
  _ACCESSREPLY._serialized_start=145
  _ACCESSREPLY._serialized_end=174
  _MKDIRREQUEST._serialized_start=176
  _MKDIRREQUEST._serialized_end=218
  _MKDIRREPLY._serialized_start=220
  _MKDIRREPLY._serialized_end=248
  _RMDIRREQUEST._serialized_start=250
  _RMDIRREQUEST._serialized_end=278
  _RMDIRREPLY._serialized_start=280
  _RMDIRREPLY._serialized_end=308
  _READDIRREQUEST._serialized_start=310
  _READDIRREQUEST._serialized_end=340
  _READDIRREPLY._serialized_start=342
  _READDIRREPLY._serialized_end=370
  _GETATTRREQUEST._serialized_start=372
  _GETATTRREQUEST._serialized_end=402
  _GETATTRREPLY._serialized_start=405
  _GETATTRREPLY._serialized_end=533
  _OPENREQUEST._serialized_start=535
  _OPENREQUEST._serialized_end=577
  _OPENREPLY._serialized_start=579
  _OPENREPLY._serialized_end=602
  _READREQUEST._serialized_start=604
  _READREQUEST._serialized_end=681
  _READREPLY._serialized_start=683
  _READREPLY._serialized_end=708
  _WRITEREQUEST._serialized_start=710
  _WRITEREQUEST._serialized_end=790
  _WRITEREPLY._serialized_start=792
  _WRITEREPLY._serialized_end=822
  _TRUNCATEREQUEST._serialized_start=824
  _TRUNCATEREQUEST._serialized_end=869
  _TRUNCATEREPLY._serialized_start=871
  _TRUNCATEREPLY._serialized_end=902
  _CHOWNREQUEST._serialized_start=904
  _CHOWNREQUEST._serialized_end=958
  _CHOWNREPLY._serialized_start=960
  _CHOWNREPLY._serialized_end=988
  _CREATEREQUEST._serialized_start=990
  _CREATEREQUEST._serialized_end=1072
  _CREATEREPLY._serialized_start=1074
  _CREATEREPLY._serialized_end=1099
  _FLUSHREQUEST._serialized_start=1101
  _FLUSHREQUEST._serialized_end=1127
  _FLUSHREPLY._serialized_start=1129
  _FLUSHREPLY._serialized_end=1157
  _CLOSEREQUEST._serialized_start=1159
  _CLOSEREQUEST._serialized_end=1185
  _CLOSEREPLY._serialized_start=1187
  _CLOSEREPLY._serialized_end=1215
  _MKNODREQUEST._serialized_start=1217
  _MKNODREQUEST._serialized_end=1272
  _MKNODREPLY._serialized_start=1274
  _MKNODREPLY._serialized_end=1302
  _CHMODREQUEST._serialized_start=1304
  _CHMODREQUEST._serialized_end=1346
  _CHMODREPLY._serialized_start=1348
  _CHMODREPLY._serialized_end=1376
  _UNLINKREQUEST._serialized_start=1378
  _UNLINKREQUEST._serialized_end=1407
  _UNLINKREPLY._serialized_start=1409
  _UNLINKREPLY._serialized_end=1438
  _RENAMEREQUEST._serialized_start=1440
  _RENAMEREQUEST._serialized_end=1481
  _RENAMEREPLY._serialized_start=1483
  _RENAMEREPLY._serialized_end=1512
  _LINKREQUEST._serialized_start=1514
  _LINKREQUEST._serialized_end=1557
  _LINKREPLY._serialized_start=1559
  _LINKREPLY._serialized_end=1586
  _UTIMEREQUEST._serialized_start=1588
  _UTIMEREQUEST._serialized_end=1646
  _UTIMEREPLY._serialized_start=1648
  _UTIMEREPLY._serialized_end=1676
  _READLINKREQUEST._serialized_start=1678
  _READLINKREQUEST._serialized_end=1723
  _READLINKREPLY._serialized_start=1725
  _READLINKREPLY._serialized_end=1758
  _FILESYSTEM._serialized_start=1761
  _FILESYSTEM._serialized_end=3101
# @@protoc_insertion_point(module_scope)
