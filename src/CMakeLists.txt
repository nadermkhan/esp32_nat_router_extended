FILE(GLOB_RECURSE app_sources ${CMAKE_SOURCE_DIR}/src/*.*)

idf_component_register(SRCS ${app_sources} INCLUDE_DIRS ".")

target_add_binary_data(${COMPONENT_TARGET} "pages/favicon.ico" BINARY)
target_add_binary_data(${COMPONENT_TARGET} "pages/index.html" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "pages/assets/index-iP8dXgYc.js" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "pages/assets/index-O1a2Fugk.css" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "pages/assets/router-DuyDbDLs.js" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "pages/assets/ui-CGN5kbBo.js" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "pages/assets/vendor-dQk0gtQ5.js" TEXT)
