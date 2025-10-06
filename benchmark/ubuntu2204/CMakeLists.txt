# Collect plain scripts from source dir
file(GLOB shell_scripts "${CMAKE_CURRENT_SOURCE_DIR}/*.sh")
file(GLOB python_scripts "${CMAKE_CURRENT_SOURCE_DIR}/*.py")

# Configure and add scripts that end in *.sh.in
file(GLOB shell_script_templates "${CMAKE_CURRENT_SOURCE_DIR}/*.sh.in")
foreach(template_file ${shell_script_templates})
  get_filename_component(template_name ${template_file} NAME_WE)
  set(configured_file "${CMAKE_CURRENT_BINARY_DIR}/${template_name}.sh")
  configure_file(${template_file} ${configured_file} @ONLY)
  list(APPEND shell_scripts ${configured_file})
endforeach()

install(PROGRAMS ${shell_scripts} ${python_scripts} bzip2-test.md5
  DESTINATION benchmark
  COMPONENT autojit-bench-scripts
)

add_custom_target(install-autojit-bench-scripts
  COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR} --component autojit-bench-scripts
  COMMENT "Installing AutoJIT benchmark scripts"
)
