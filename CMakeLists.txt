cmake_minimum_required(VERSION 3.21.1)
project(CardGuard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets)
get_target_property(CARDGUARD_QT_CORE_TYPE Qt6::Core TYPE)
if(CARDGUARD_QT_CORE_TYPE STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR "CardGuard requires a shared Qt build. Use the dynamically linked Qt SDK.")
endif()
qt_standard_project_setup()

qt_add_executable(cardguard WIN32 frontend/main.cpp)
target_link_libraries(cardguard PRIVATE Qt6::Widgets)
set_target_properties(cardguard PROPERTIES OUTPUT_NAME "CardGuard")

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

set(CARDGUARD_LICENSE_CLIENT "" CACHE FILEPATH "Optional absolute path to the built Rust license-client executable")
if(CARDGUARD_LICENSE_CLIENT)
    if(NOT IS_ABSOLUTE "${CARDGUARD_LICENSE_CLIENT}" OR NOT EXISTS "${CARDGUARD_LICENSE_CLIENT}"
       OR IS_DIRECTORY "${CARDGUARD_LICENSE_CLIENT}")
        message(FATAL_ERROR "CARDGUARD_LICENSE_CLIENT must point to an existing executable using an absolute path.")
    endif()
    if(WIN32)
        set(CARDGUARD_CLIENT_FILE_NAME "license-client.exe")
    else()
        set(CARDGUARD_CLIENT_FILE_NAME "license-client")
    endif()
    get_filename_component(CARDGUARD_CLIENT_INPUT_NAME "${CARDGUARD_LICENSE_CLIENT}" NAME)
    if(NOT CARDGUARD_CLIENT_INPUT_NAME STREQUAL CARDGUARD_CLIENT_FILE_NAME)
        message(FATAL_ERROR "Only ${CARDGUARD_CLIENT_FILE_NAME} may be bundled with the verifier.")
    endif()
    add_custom_target(cardguard_verifier
        COMMAND "${CMAKE_COMMAND}" -E make_directory "$<TARGET_FILE_DIR:cardguard>"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${CARDGUARD_LICENSE_CLIENT}"
            "$<TARGET_FILE_DIR:cardguard>/${CARDGUARD_CLIENT_FILE_NAME}"
        DEPENDS "${CARDGUARD_LICENSE_CLIENT}"
        COMMENT "Copying Rust verifier beside the Qt executable"
        VERBATIM
    )
    add_dependencies(cardguard cardguard_verifier)
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
