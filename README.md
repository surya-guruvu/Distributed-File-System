#To run the code, you need to execute below commands
- python3 -m grpc_tools.protoc --proto_path=. ./filesystem.proto --python_out=. --grpc_python_out=.
- python3 serverfs.py
- python3 clientfs.py "/home/ee1190481/Downloads/example1" "/home/ee1190481/Downloads/example"
