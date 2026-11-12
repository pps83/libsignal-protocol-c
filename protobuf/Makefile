all:
	protoc --upb_out=../src/ --upb_minitable_out=../src/ WhisperTextProtocol.proto LocalStorageProtocol.proto FingerprintProtocol.proto
	rm -f ../src/*.upb.c
