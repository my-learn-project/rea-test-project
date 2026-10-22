cmake_minimum_required(VERSION 3.21.1)
project(CardGuard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Concurrent)
get_target_property(CARDGUARD_QT_CORE_TYPE Qt6::Core TYPE)
if(CARDGUARD_QT_CORE_TYPE STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR "CardGuard requires a shared Qt build. Use the dynamically linked Qt SDK.")
endif()
qt_standard_project_setup()

qt_add_executable(cardguard WIN32 frontend/main.cpp)
target_link_libraries(cardguard PRIVATE Qt6::Widgets Qt6::Concurrent)
set_target_properties(cardguard PROPERTIES OUTPUT_NAME "CardGuard")

# The GUI calls the verifier in-process; a replaceable helper is not a trust boundary.
set(CARDGUARD_RUST_LIBRARY "" CACHE FILEPATH "Absolute path to the Rust license_client static library")
set(CARDGUARD_POLICY_OBJECT "" CACHE FILEPATH "Absolute path to the verified xollvm policy object")
foreach(required_path CARDGUARD_RUST_LIBRARY CARDGUARD_POLICY_OBJECT)
    if(NOT IS_ABSOLUTE "${${required_path}}" OR NOT EXISTS "${${required_path}}"
       OR IS_DIRECTORY "${${required_path}}")
        message(FATAL_ERROR "${required_path} must be an existing absolute file. Use the complete build script.")
    endif()
endforeach()
add_library(cardguard_rust STATIC IMPORTED)
set_target_properties(cardguard_rust PROPERTIES IMPORTED_LOCATION "${CARDGUARD_RUST_LIBRARY}")
set_source_files_properties("${CARDGUARD_POLICY_OBJECT}" PROPERTIES EXTERNAL_OBJECT TRUE)
target_sources(cardguard PRIVATE "${CARDGUARD_POLICY_OBJECT}")
target_link_libraries(cardguard PRIVATE cardguard_rust)
if(WIN32)
    set(CARDGUARD_WINDOWS_IMPORT_LIBRARY "" CACHE FILEPATH "windows-targets import library used by Rust")
    if(NOT EXISTS "${CARDGUARD_WINDOWS_IMPORT_LIBRARY}")
        message(FATAL_ERROR "Provide CARDGUARD_WINDOWS_IMPORT_LIBRARY from the locked Cargo dependency.")
    endif()
    target_link_libraries(cardguard PRIVATE ws2_32 userenv bcrypt ntdll advapi32 dbghelp "${CARDGUARD_WINDOWS_IMPORT_LIBRARY}")
elseif(APPLE)
    target_link_libraries(cardguard PRIVATE "-framework Security" "-framework CoreFoundation" iconv resolv)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(policy-tests tests/authorization_policy_test.cpp "${CARDGUARD_POLICY_OBJECT}")
    target_include_directories(policy-tests PRIVATE frontend)
    if(MSVC)
        target_compile_options(policy-tests PRIVATE /guard:cf /utf-8)
        target_link_options(policy-tests PRIVATE /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /guard:cf)
    endif()
    add_test(NAME virtualized-authorization-policy COMMAND policy-tests)
endif()

if(APPLE)
    set_target_properties(cardguard PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.example.cardguard"
        MACOSX_BUNDLE_BUNDLE_NAME "CardGuard"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/frontend/Info.plist.in"
    )
endif()

if(MSVC)
    target_compile_options(cardguard PRIVATE /W4 /sdl /guard:cf /utf-8)
    target_link_options(cardguard PRIVATE /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /guard:cf)
else()
    target_compile_options(cardguard PRIVATE -Wall -Wextra -Wpedantic)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(cardguard PRIVATE -fstack-protector-strong -fPIE)
        target_link_options(cardguard PRIVATE -pie -Wl,-z,relro,-z,now)
    elseif(APPLE)
        target_compile_options(cardguard PRIVATE -fstack-protector-strong -fPIE)
        target_link_options(cardguard PRIVATE -Wl,-pie)
    endif()
endif()

install(TARGETS cardguard RUNTIME DESTINATION . BUNDLE DESTINATION .)
