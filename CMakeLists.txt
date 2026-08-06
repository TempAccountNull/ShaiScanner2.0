cmake_minimum_required(VERSION 3.24)
project(ShaiHulud2Scanner VERSION 1.7.6 LANGUAGES CXX RC)

if(NOT WIN32)
    message(FATAL_ERROR "Shai-Hulud 2.0 Scanner is a Windows application.")
endif()

# Visual Studio's ZERO_CHECK target can re-run CMake once per parallel target.
# Dependencies are prepared before configuration, so regeneration is unnecessary
# and can otherwise cause concurrent processes to contend over the same files.
set(CMAKE_SUPPRESS_REGENERATION ON CACHE BOOL
    "Disable automatic CMake regeneration during parallel Visual Studio builds" FORCE)

set(SHAIHULUD_IMGUI_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui-1.92.9b"
    CACHE PATH "Existing Dear ImGui v1.92.9b source directory")

file(TO_CMAKE_PATH "${SHAIHULUD_IMGUI_SOURCE_DIR}" imgui_SOURCE_DIR)
set(_imgui_required_files
    imgui.cpp
    imgui.h
    imgui_draw.cpp
    imgui_tables.cpp
    imgui_widgets.cpp
    backends/imgui_impl_win32.cpp
    backends/imgui_impl_win32.h
    backends/imgui_impl_dx11.cpp
    backends/imgui_impl_dx11.h
)
foreach(_imgui_file IN LISTS _imgui_required_files)
    if(NOT EXISTS "${imgui_SOURCE_DIR}/${_imgui_file}")
        message(FATAL_ERROR
            "Dear ImGui v1.92.9b is not prepared at '${imgui_SOURCE_DIR}'.\n"
            "Run tools\\prepare_imgui.ps1 or build-release.bat before configuring.")
    endif()
endforeach()
message(STATUS "Using pre-prepared Dear ImGui source: ${imgui_SOURCE_DIR}")

add_library(shaihulud_imgui STATIC
    "${imgui_SOURCE_DIR}/imgui.cpp"
    "${imgui_SOURCE_DIR}/imgui_draw.cpp"
    "${imgui_SOURCE_DIR}/imgui_tables.cpp"
    "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp"
)

target_include_directories(shaihulud_imgui PUBLIC
    "${imgui_SOURCE_DIR}"
    "${imgui_SOURCE_DIR}/backends"
)

target_compile_features(shaihulud_imgui PUBLIC cxx_std_20)
target_compile_definitions(shaihulud_imgui PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
)

if(MSVC)
    target_compile_options(shaihulud_imgui PRIVATE
        /W3
        /permissive-
        /EHsc
        /utf-8
    )
endif()

set_source_files_properties(src/resources.rc PROPERTIES
    OBJECT_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/shaihulud.ico;${CMAKE_CURRENT_SOURCE_DIR}/src/resource.h"
)

add_executable(ShaiHulud2Scanner WIN32
    src/Main.cpp
    src/Scanner.cpp
    src/FeedUpdater.cpp
    src/StepSecurityExtractor.cpp
    src/MaliciousHashLoader.cpp
    src/DebugLog.cpp
    src/AffectedPackages.generated.cpp
    src/resources.rc
    src/resource.h
    src/shaihulud.ico
    src/app.manifest
)

target_compile_features(ShaiHulud2Scanner PRIVATE cxx_std_20)

target_compile_definitions(ShaiHulud2Scanner PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
)

if(MSVC)
    target_compile_options(ShaiHulud2Scanner PRIVATE
        /W4
        /permissive-
        /EHsc
        /utf-8
    )
    target_link_options(ShaiHulud2Scanner PRIVATE
        /SUBSYSTEM:WINDOWS
        /MANIFESTUAC:NO
    )
endif()

enable_testing()

add_executable(StepSecurityExtractorTests
    tests/StepSecurityExtractorTests.cpp
    src/StepSecurityExtractor.cpp
    src/DebugLog.cpp
)
target_compile_features(StepSecurityExtractorTests PRIVATE cxx_std_20)
target_include_directories(StepSecurityExtractorTests PRIVATE src)
if(MSVC)
    target_compile_options(StepSecurityExtractorTests PRIVATE
        /W4
        /permissive-
        /EHsc
        /utf-8
    )
endif()
add_test(NAME StepSecurityExtractorTests COMMAND StepSecurityExtractorTests)
target_link_libraries(StepSecurityExtractorTests PRIVATE user32)

add_executable(MaliciousHashLoaderTests
    tests/MaliciousHashLoaderTests.cpp
    src/MaliciousHashLoader.cpp
)
target_compile_features(MaliciousHashLoaderTests PRIVATE cxx_std_20)
target_include_directories(MaliciousHashLoaderTests PRIVATE src)
if(MSVC)
    target_compile_options(MaliciousHashLoaderTests PRIVATE
        /W4
        /permissive-
        /EHsc
        /utf-8
    )
endif()
add_test(NAME MaliciousHashLoaderTests COMMAND MaliciousHashLoaderTests "${CMAKE_SOURCE_DIR}/malicious_hashes.json")

target_link_libraries(ShaiHulud2Scanner PRIVATE
    shaihulud_imgui
    bcrypt
    comdlg32
    d3d11
    dxgi
    dwmapi
    imm32
    ole32
    shell32
    user32
    winhttp
)

set(SHAIHULUD_FEEDS
    socket-chaindrop.csv
    safedep-mini-shai-hulud.csv
    wiz-shai-hulud-2-packages.csv
    datadog-keyv-malicious-packages.csv
    chaindrop-compromised-packages.csv
    jfrog-shai-hulud-2-packages.csv
    community-shai-hulud-aggregate.csv
    feed-manifest.json
)

add_custom_command(TARGET ShaiHulud2Scanner POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "$<TARGET_FILE_DIR:ShaiHulud2Scanner>/data"
)

add_custom_command(TARGET ShaiHulud2Scanner POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/malicious_hashes.json"
        "$<TARGET_FILE_DIR:ShaiHulud2Scanner>/malicious_hashes.json"
)

foreach(feed IN LISTS SHAIHULUD_FEEDS)
    add_custom_command(TARGET ShaiHulud2Scanner POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/data/${feed}"
            "$<TARGET_FILE_DIR:ShaiHulud2Scanner>/data/${feed}"
    )
endforeach()

if(EXISTS "${imgui_SOURCE_DIR}/LICENSE.txt")
    add_custom_command(TARGET ShaiHulud2Scanner POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${imgui_SOURCE_DIR}/LICENSE.txt"
            "$<TARGET_FILE_DIR:ShaiHulud2Scanner>/Dear-ImGui-LICENSE.txt"
    )
endif()
