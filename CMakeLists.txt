cmake_minimum_required(VERSION 2.6)

PROJECT(ucentral-wifi C)
ADD_DEFINITIONS(-Os -ggdb -Wextra -Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-unused-parameter)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES main.c nl80211.c ubus.c)

FIND_LIBRARY(ubus NAMES ubus)
FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(nl-tiny NAMES nl-tiny)
FIND_PATH(ubus_include_dir NAMES libubus.h)
INCLUDE_DIRECTORIES(${ubox_include_dir} ${ubus_include_dir})

ADD_EXECUTABLE(ucentral-wifi ${SOURCES})

TARGET_LINK_LIBRARIES(ucentral-wifi ${ubox} ${ubus} ${nl-tiny})

INSTALL(TARGETS ucentral-wifi
	RUNTIME DESTINATION sbin
)
