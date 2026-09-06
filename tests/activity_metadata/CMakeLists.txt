cmake_minimum_required(VERSION 3.25)
project(SunriseActivityMetadataTests LANGUAGES CXX)
enable_testing()

set(SUNRISE_SOURCE "${CMAKE_CURRENT_LIST_DIR}/../../Sunrise/src")
add_executable(activity_metadata_tests
    activity_metadata_tests.cpp
    "${SUNRISE_SOURCE}/middleware/content/packages/tables/definition_index_table.cpp"
    "${SUNRISE_SOURCE}/middleware/content/packages/tables/activity_metadata_reader.cpp"
    "${SUNRISE_SOURCE}/middleware/content/packages/tables/activity_type_mapping.cpp"
    "${SUNRISE_SOURCE}/middleware/content/packages/tables/localized_string_reader.cpp")
target_include_directories(activity_metadata_tests PRIVATE "${SUNRISE_SOURCE}")
target_compile_features(activity_metadata_tests PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(activity_metadata_tests PRIVATE /W4 /WX)
else()
    target_compile_options(activity_metadata_tests PRIVATE -Wall -Wextra -Werror)
endif()
if(WIN32)
    target_compile_definitions(activity_metadata_tests PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_sources(activity_metadata_tests PRIVATE
        "${SUNRISE_SOURCE}/state/build_data/cache/records/cache_scenario_records.cpp"
        "${SUNRISE_SOURCE}/state/build_data/scenarios/scenario_catalog.cpp")
endif()
add_test(NAME activity_metadata COMMAND activity_metadata_tests)
