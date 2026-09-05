cmake_minimum_required(VERSION 3.20)
project(SunrisePortableTests LANGUAGES CXX)
enable_testing()
add_executable(socket_row_relocation_test socket_row_relocation_test.cpp)
target_compile_features(socket_row_relocation_test PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(socket_row_relocation_test PRIVATE /W4 /WX /UNDEBUG)
else()
    target_compile_options(socket_row_relocation_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
endif()
add_test(NAME socket_row_relocation
    COMMAND socket_row_relocation_test "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/socket_rows.hex")
add_executable(lore_visibility_test lore_visibility_test.cpp)
target_compile_features(lore_visibility_test PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(lore_visibility_test PRIVATE /W4 /WX /UNDEBUG)
else()
    target_compile_options(lore_visibility_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
endif()
add_test(NAME lore_visibility COMMAND lore_visibility_test)

# The production catalyst catalog uses the Windows SRW lock adapter.
if(WIN32)
    set(SRC "${CMAKE_CURRENT_SOURCE_DIR}/../Sunrise/src")
    add_executable(catalyst_projection_test catalyst_projection_test.cpp
        "${SRC}/state/build_data/items/catalysts/exotic_catalyst_catalog.cpp"
        "${SRC}/state/progression/seasonal_experience.cpp"
        "${SRC}/core/filesystem/path.cpp"
        "${SRC}/state/build_data/cache/records/cache_exotic_catalyst_record_codec.cpp"
        "${SRC}/middleware/encoding/bit_writer.cpp"
        "${SRC}/middleware/encoding/bit_reader.cpp"
        "${SRC}/middleware/web_service/web_service_envelope.cpp"
        "${SRC}/middleware/web_service/status_fields.cpp"
        "${SRC}/middleware/web_service/messages/family5_codec.cpp"
        "${SRC}/middleware/web_service/messages/opcode503_codec.cpp"
        "${SRC}/middleware/web_service/messages/opcode205_codec.cpp")
    target_include_directories(catalyst_projection_test PRIVATE "${SRC}")
    target_compile_features(catalyst_projection_test PRIVATE cxx_std_20)
    target_compile_definitions(catalyst_projection_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    if(MSVC)
        target_compile_options(catalyst_projection_test PRIVATE /W4 /WX /UNDEBUG)
    else()
        target_compile_options(catalyst_projection_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    endif()
    add_test(NAME catalyst_projection COMMAND catalyst_projection_test "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/catalyst_completion_86657.txt")
endif()
