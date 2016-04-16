add_executable( test-base64       test-base64.cpp )
add_executable( test-wireformat   test-wireformat.cpp )
target_link_libraries(test-base64     libdns crypto gtest pthread)
target_link_libraries(test-wireformat libdns crypto gtest pthread)

add_test(
  NAME test-base64
  COMMAND test-base64
)

add_test(
  NAME test-wireformat
  COMMAND test-wireformat
)

