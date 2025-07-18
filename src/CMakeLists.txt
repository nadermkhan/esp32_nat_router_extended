FILE(GLOB_RECURSE app_sources ${CMAKE_SOURCE_DIR}/src/*.*)

idf_component_register(SRCS ${app_sources} INCLUDE_DIRS ".")

target_add_binary_data(${COMPONENT_TARGET} "pages/favicon.ico" BINARY)
target_add_binary_data(${COMPONENT_TARGET} "pages/index.html" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "pages/index.js" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "pages/index.css" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "pages/router.js" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "pages/ui.js" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "pages/vendor.js" TEXT)