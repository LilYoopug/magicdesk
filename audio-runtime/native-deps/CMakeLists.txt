cmake_minimum_required(VERSION 3.24)
project(MagicDeskAudioDependencies LANGUAGES C)
include(ExternalProject)
find_program(MESON meson REQUIRED)
find_program(PATCH patch REQUIRED)
set(prefix "${CMAKE_BINARY_DIR}/prefix")
set(compiler "${CMAKE_C_COMPILER}")
if(CMAKE_C_COMPILER_TARGET)
    list(APPEND compiler "--target=${CMAKE_C_COMPILER_TARGET}")
endif()
if(CMAKE_SYSROOT)
    list(APPEND compiler "--sysroot=${CMAKE_SYSROOT}")
endif()
function(meson_array out)
    set(items "")
    foreach(item IN LISTS ARGN)
        string(REPLACE "\\" "\\\\" item "${item}")
        string(REPLACE "'" "\\'" item "${item}")
        string(APPEND items "'${item}',")
    endforeach()
    set(${out} "[${items}]" PARENT_SCOPE)
endfunction()
separate_arguments(flags UNIX_COMMAND "${CMAKE_C_FLAGS}")
separate_arguments(link_flags UNIX_COMMAND "${CMAKE_SHARED_LINKER_FLAGS}")
meson_array(MD_CC ${compiler})
meson_array(MD_AR "${CMAKE_AR}")
meson_array(MD_FLAGS ${flags} -DANDROID -fPIC -include ${CMAKE_CURRENT_SOURCE_DIR}/android-compat.h)
meson_array(MD_LINK_FLAGS ${link_flags} -Wl,-z,max-page-size=16384)
configure_file(android.ini.in android.ini @ONLY)
file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/android.patch" android_patch)
file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/admission.patch" admission_patch)
string(SHA256 patch_key "${android_patch}:${admission_patch}")
string(SUBSTRING "${patch_key}" 0 16 patch_key)
ExternalProject_Add(pipewire
    PREFIX "${CMAKE_BINARY_DIR}/pipewire-${patch_key}"
    DOWNLOAD_DIR "${CMAKE_BINARY_DIR}/downloads"
    URL https://gitlab.freedesktop.org/pipewire/pipewire/-/archive/1.4.9/pipewire-1.4.9.tar.bz2
    URL_HASH SHA256=e606aa3f6d53ec4c56fe35034d35cadfe0bbea1a5275e4e006dd7d1abaec6b92
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    PATCH_COMMAND ${PATCH} --batch --forward -p1 -i ${CMAKE_CURRENT_SOURCE_DIR}/android.patch
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env --unset=CFLAGS --unset=CPPFLAGS --unset=LDFLAGS
        "PKG_CONFIG_LIBDIR=${prefix}/lib/pkgconfig" "PKG_CONFIG_PATH="
        ${MESON} setup --clearcache --reconfigure <BINARY_DIR> <SOURCE_DIR>
        --cross-file=${CMAKE_CURRENT_BINARY_DIR}/android.ini --prefix=${prefix} --libdir=lib
        --buildtype=release --wrap-mode=nofallback -Dauto_features=disabled
        -Dtests=disabled -Dexamples=disabled -Ddbus=disabled -Dflatpak=disabled
        -Dsession-managers=[] -Dpipewire-jack=disabled -Dpipewire-v4l2=disabled
        -Dsystemd-user-service=disabled -Dlegacy-rtkit=false -Drlimits-install=false
        -Dvideoconvert=disabled -Dvideotestsrc=disabled -Daudiotestsrc=disabled
    BUILD_COMMAND ${MESON} compile -C <BINARY_DIR> -j 4
    INSTALL_COMMAND ${MESON} install -C <BINARY_DIR>
        COMMAND ${CMAKE_COMMAND} -E make_directory ${prefix}/licenses
        COMMAND ${CMAKE_COMMAND} -E copy <SOURCE_DIR>/LICENSE <SOURCE_DIR>/COPYING ${prefix}/licenses
    BUILD_BYPRODUCTS ${prefix}/lib/libpipewire-0.3.so)
ExternalProject_Add_StepDependencies(pipewire configure
    ${CMAKE_CURRENT_BINARY_DIR}/android.ini ${CMAKE_CURRENT_SOURCE_DIR}/android-compat.h)
ExternalProject_Add_StepDependencies(pipewire patch ${CMAKE_CURRENT_SOURCE_DIR}/android.patch)
ExternalProject_Add_Step(pipewire admission
    COMMAND ${PATCH} --batch --forward -p1 -d <SOURCE_DIR> -i ${CMAKE_CURRENT_SOURCE_DIR}/admission.patch
    DEPENDEES patch DEPENDERS configure
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/admission.patch)

add_library(magicdesk_audio SHARED ../src/main/cpp/audio.c)
add_dependencies(magicdesk_audio pipewire)
target_include_directories(magicdesk_audio PRIVATE ${prefix}/include/pipewire-0.3 ${prefix}/include/spa-0.2)
target_compile_options(magicdesk_audio PRIVATE -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter)
target_link_options(magicdesk_audio PRIVATE -Wl,-z,max-page-size=16384 -Wl,-z,defs)
target_link_libraries(magicdesk_audio PRIVATE ${prefix}/lib/libpipewire-0.3.so aaudio log dl m)
set_target_properties(magicdesk_audio PROPERTIES BUILD_RPATH "" INSTALL_RPATH "" SKIP_BUILD_RPATH TRUE)
add_executable(audio-ring-test ../tests/ring.c)
target_include_directories(audio-ring-test PRIVATE ../src/main/cpp)
target_compile_options(audio-ring-test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
enable_testing()
add_test(NAME audio-ring COMMAND audio-ring-test)
add_executable(audio-test-host ../src/main/cpp/audio.c)
add_dependencies(audio-test-host pipewire)
target_compile_definitions(audio-test-host PRIVATE MD_AUDIO_TEST_HOST)
target_include_directories(audio-test-host PRIVATE ${prefix}/include/pipewire-0.3 ${prefix}/include/spa-0.2)
target_link_libraries(audio-test-host PRIVATE ${prefix}/lib/libpipewire-0.3.so aaudio log dl m)
add_executable(audio-test-client ../tests/client.c)
add_dependencies(audio-test-client pipewire)
target_include_directories(audio-test-client PRIVATE ${prefix}/include/pipewire-0.3 ${prefix}/include/spa-0.2)
target_link_libraries(audio-test-client PRIVATE ${prefix}/lib/libpipewire-0.3.so)
