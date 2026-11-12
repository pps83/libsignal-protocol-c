if(BUILD_SHARED_LIBS)
	find_library(M_LIB m)
endif()

set(PROTOBUF_SOURCE_DIR "" CACHE PATH "Source tree of protobuf; its upb runtime is compiled into the library")
if(NOT PROTOBUF_SOURCE_DIR)
	message(FATAL_ERROR "Set PROTOBUF_SOURCE_DIR to a protobuf source tree that holds upb/")
endif()

include_directories(
	.
	curve25519/ed25519/nacl_includes
	curve25519/ed25519/additions
	curve25519/ed25519/sha512
	curve25519/ed25519
	curve25519
	${PROTOBUF_SOURCE_DIR}
	${PROTOBUF_SOURCE_DIR}/third_party/utf8_range
)

set(protobuf_SRCS
	LocalStorageProtocol.upb_minitable.c
	WhisperTextProtocol.upb_minitable.c
	FingerprintProtocol.upb_minitable.c
	${PROTOBUF_SOURCE_DIR}/upb/base/status.c
	${PROTOBUF_SOURCE_DIR}/upb/hash/common.c
	${PROTOBUF_SOURCE_DIR}/upb/mem/alloc.c
	${PROTOBUF_SOURCE_DIR}/upb/mem/arena.c
	${PROTOBUF_SOURCE_DIR}/upb/message/array.c
	${PROTOBUF_SOURCE_DIR}/upb/message/map.c
	${PROTOBUF_SOURCE_DIR}/upb/message/map_sorter.c
	${PROTOBUF_SOURCE_DIR}/upb/message/message.c
	${PROTOBUF_SOURCE_DIR}/upb/message/unknown_fields.c
	${PROTOBUF_SOURCE_DIR}/upb/message/internal/extension.c
	${PROTOBUF_SOURCE_DIR}/upb/message/internal/message.c
	${PROTOBUF_SOURCE_DIR}/upb/mini_table/extension_registry.c
	${PROTOBUF_SOURCE_DIR}/upb/mini_table/message.c
	${PROTOBUF_SOURCE_DIR}/upb/port/port.c
	${PROTOBUF_SOURCE_DIR}/upb/wire/decode.c
	${PROTOBUF_SOURCE_DIR}/upb/wire/encode.c
	${PROTOBUF_SOURCE_DIR}/upb/wire/eps_copy_input_stream.c
	${PROTOBUF_SOURCE_DIR}/upb/wire/reader.c
	${PROTOBUF_SOURCE_DIR}/upb/wire/internal/back_alloc.c
	${PROTOBUF_SOURCE_DIR}/upb/wire/internal/decoder.c
	${PROTOBUF_SOURCE_DIR}/upb/wire/internal/encoder.c
	${PROTOBUF_SOURCE_DIR}/third_party/utf8_range/utf8_range.c
)

if(MSVC)
	set_source_files_properties(${protobuf_SRCS} PROPERTIES COMPILE_OPTIONS /Zc:preprocessor)
endif()

set(signal_protocol_SRCS
	vpool.c
	vpool.h
	signal_protocol.c
	signal_protocol.h
	signal_protocol_types.h
	signal_protocol_internal.h
	curve.c
	curve.h
	hkdf.c
	hkdf.h
	ratchet.c
	ratchet.h
	protocol.c
	protocol.h
	session_state.c
	session_state.h
	session_record.c
	session_record.h
	session_pre_key.c
	session_pre_key.h
	session_builder.c
	session_builder.h
	session_builder_internal.h
	session_cipher.c
	session_cipher.h
	key_helper.c
	key_helper.h
	sender_key.c
	sender_key.h
	sender_key_state.c
	sender_key_state.h
	sender_key_record.c
	sender_key_record.h
	group_session_builder.c
	group_session_builder.h
	group_cipher.c
	group_cipher.h
	fingerprint.c
	fingerprint.h
	device_consistency.c
	device_consistency.h
)

add_subdirectory(curve25519)

add_library(signal-protocol-c
	${protobuf_SRCS}
	${signal_protocol_SRCS}
	$<TARGET_OBJECTS:curve25519>
)

if(BUILD_SHARED_LIBS)
	target_link_libraries(signal-protocol-c ${M_LIB})
	set_target_properties(signal-protocol-c PROPERTIES
		VERSION ${SIGNAL_PROTOCOL_C_VERSION}
		SOVERSION ${SIGNAL_PROTOCOL_C_VERSION_MAJOR}
	)
endif()

INSTALL(
	FILES
	signal_protocol.h
	signal_protocol_types.h
	curve.h
	hkdf.h
	ratchet.h
	protocol.h
	session_state.h
	session_record.h
	session_pre_key.h
	session_builder.h
	session_cipher.h
	key_helper.h
	sender_key.h
	sender_key_state.h
	sender_key_record.h
	group_session_builder.h
	group_cipher.h
	fingerprint.h
	device_consistency.h
	DESTINATION ${INCLUDE_INSTALL_DIR}/signal
)

INSTALL(TARGETS signal-protocol-c
	LIBRARY DESTINATION ${LIB_INSTALL_DIR}
	RUNTIME DESTINATION ${BIN_INSTALL_DIR}
	ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c.pc.in
		${CMAKE_CURRENT_BINARY_DIR}/libsignal-protocol-c.pc @ONLY)

INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsignal-protocol-c.pc DESTINATION "${INSTALL_PKGCONFIG_DIR}")
