 # 设置cmake的最低版本要求
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
# 制定c++的编译器版本为c++11
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)

# 设置工程名称
project(securefs)
# 启用测试
enable_testing()
# cmake_policy的作用是保证不同版本的工具包兼容，使用NEW来声明后续代码依赖于此policy
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0069 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)

# 检查编译器是否支持interprocedural optimization
include(CheckIPOSupported)
check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT error)
# 如果支持则开启interprocedural optimization
if(IPO_SUPPORTED)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL ON)
endif()
# 从来不尝试查找framework，具体作用？
set(CMAKE_FIND_FRAMEWORK NEVER)

# 执行"uname -m"命令，输出系统的架构（x86_64），存到architecture这个变量中
execute_process(COMMAND bash -c "uname -m" OUTPUT_VARIABLE architecture)

# 设置cmake查找module时的路径
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake-modules/")
# 引入GetGitRevisionDescription模块，可以操作git的信息
include(GetGitRevisionDescription)
git_describe(GIT_VERSION --tags)
# 需要用configure_file()进行配置，配置后git-version.cpp里面GIT_VERSION对应的变量会更新为获取到的数值
configure_file(${CMAKE_SOURCE_DIR}/sources/git-version.cpp.in
               ${CMAKE_BINARY_DIR}/git-version.cpp)

# 复制导入cryptopp的CMakeLists.txt文件，为了使cryptopp这个外部库在cmake中能用
file(COPY ${CMAKE_SOURCE_DIR}/external/cmake-cryptopp/CMakeLists.txt
     DESTINATION ${CMAKE_SOURCE_DIR}/external/cryptopp)

# 如果此时操作系统是UNIX
if(UNIX)
    # 查找fuse.h，找的会将结果（所在目录）存在FUSE_INCLUDE_DIR变量中
    find_path(FUSE_INCLUDE_DIR fuse.h PATHS /usr/local/include)
    # 查找fuse库，找的会将结果（全路径）存在FUSE_LIBRARIES变量中
    find_library(FUSE_LIBRARIES fuse PATHS /usr/local/lib)
    # 将fuse所在的目录加入到搜索目录中，使编译器能找到fuse.h
    include_directories(${FUSE_INCLUDE_DIR})
    # 将fuse库链接到后面的所有target中
    link_libraries(${FUSE_LIBRARIES})
    # 配置编译器，设置warning的情况
    add_compile_options(-Wall -Wextra -Wno-unknown-pragmas)

    # 如果是apple的操作系统
    if(APPLE)
        # 将apple系统独有的库链接到后面的target中，参数表示？
        link_libraries(-Wl,-dead_strip)
    else()
    # 如果不是apple的系统，那就是linux的咯
        # 进行编译配置和库链接
        add_compile_options(-pthread)
        link_libraries(-pthread)
    endif()
    # 链接unix中的dlopen和dlclose库
    link_libraries(${CMAKE_DL_LIBS})
else()
# 如果不是UNIX系统，那就是Windows系统咯
    # add_definitions的功能和C++中的#define是一样的，在C++文件中可以使用下述定义的参数
    add_definitions(-DNOMINMAX=1)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS=1)
    add_definitions(-D__STDC__=1)
    # 定义WINFSP_PREFIX这个变量
    if(NOT WINFSP_PREFIX)
        message("WINFSP_PREFIX not set, fallback to default value")
        set(WINFSP_PREFIX "C:/Program Files (x86)/WinFsp")
    endif()
    # 判断指针大小，若为8字节则设置系统架构为64位，否则为32位
    if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
        set(ARCH x64)
    else()
        set(ARCH x86)
    endif()
    # 定义FUSE_INCLUDE_DIR这个变量，表示fuse头文件所在的目录，并在下面几行加入到搜索路径
    set(FUSE_INCLUDE_DIR ${WINFSP_PREFIX}/inc/fuse)
    include_directories(${WINFSP_PREFIX}/inc)
    include_directories(${FUSE_INCLUDE_DIR})
    # 链接到winfsp库
    link_libraries(${WINFSP_PREFIX}/lib/winfsp-${ARCH}.lib)
    link_libraries(delayimp.lib)
    # 如果使用的是MSVC编译器（visual studio）
    if(MSVC)
        link_libraries(-DELAYLOAD:winfsp-${ARCH}.dll)
        add_compile_options(/utf-8)
    elseif(MINGW)
    # 如果使用的是MINGW编译器（visual studio）
        link_libraries(-delayload=winfsp-${ARCH}.dll)
    endif()
endif()

# 如果使用的是Clang编译器，开启线程安全分析
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wthread-safety)
    # 如果有MINGW编译器
    if(MINGW)
        add_compile_options(-fansi-escape-codes -fcolor-diagnostics)
    endif()
endif()

# 定义参数，这些变量在编译的时候需要用到，否则可能出现下面错误
# [build] /usr/local/include/fuse/fuse_common.h:52:2: error: Please add -D_FILE_OFFSET_BITS=64 to your compile flags!
add_definitions(-D_REENTRANT -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=28
                -DUTF8PROC_EXPORTS=1)

# 制定单配置生成器的构建类型
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 将source文件夹加入到
include_directories(sources)
# EXTERNAL_DIR变量为“external”这个目录
set(EXTERNAL_DIR external)
# 将“external”这个目录加入到搜索路径中
include_directories(${EXTERNAL_DIR})

# CRYPTOPP_DIR变量为cryptopp所在目录
set(CRYPTOPP_DIR ${EXTERNAL_DIR}/cryptopp)
# 添加cryptopp子目录，子目录下应该包含CMakeLists.txt文件和代码文件
# 子目录会进行编译，默认将编译后的库放在输出目录下，target链接库后，target对应的cpp文件才能调用库中的头文件
add_subdirectory(${CRYPTOPP_DIR})
# 后面的target链接cryptopp-static库
link_libraries(cryptopp-static)

# 添加argon2子目录，对应的CMakeLists.txt应该是作者自己写的
add_subdirectory(${EXTERNAL_DIR}/argon2)
# 将argon2头文件所在目录加入到搜索目录中，这样cpp文件才能找到对应的头文件
include_directories(${EXTERNAL_DIR}/argon2/include)
# 后面的target链接argon2_static库
link_libraries(argon2_static)

# 将满足glob expression的文件存到SOURCES这个列表中，是列表吗？？
file(
    GLOB
    SOURCES
    sources/*.cpp
    sources/*.h
    ${EXTERNAL_DIR}/*.h
    ${EXTERNAL_DIR}/*.hpp
    ${EXTERNAL_DIR}/*.cpp
    ${CMAKE_BINARY_DIR}/git-version.cpp
    ${EXTERNAL_DIR}/utf8proc/utf8proc.h
    ${EXTERNAL_DIR}/utf8proc/utf8proc.c)
# 将满足glob expression的文件存到TEST_SOURCES这个列表中
file(GLOB TEST_SOURCES test/*.h test/*.cpp)
# 将SOURCES列表中的文件设置为securefs-static静态库
add_library(securefs-static STATIC ${SOURCES})
# 后面的target链接到securefs-static静态库
link_libraries(securefs-static)

# 如果使用MSVC（visual studio）
if(MSVC)
    # 基于指定的源文件，创建可执行文件，MSVC需要特殊的文件manifest
    add_executable(securefs main.cpp securefs.manifest)
else()
# 如果不是MSVC，不需要manifest
    add_executable(securefs main.cpp)
endif()

# 创建测试可执行文件
add_executable(securefs_test ${TEST_SOURCES})

# 创建ctest测试
add_test(NAME sec_test COMMAND securefs_test)
find_package(Python3 COMPONENTS Interpreter)
# 如果python3可用，创建一个ctest python测试用例
if(Python3_FOUND)
    add_test(
        NAME simple_test
        COMMAND ${CMAKE_COMMAND} -E env SECUREFS_BINARY=$<TARGET_FILE:securefs>
                ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/test/simple_test.py)
endif()

# 指定安装时的运行规格，安装后可直接用project name命令在命令行操作
install(TARGETS securefs DESTINATION bin)

# 如果编译器是MINGW（Windows独有）
if(MINGW)
    # 链接municode库，private表示仅当前target可用不可传播
    target_link_libraries(securefs PRIVATE -municode)
endif()
