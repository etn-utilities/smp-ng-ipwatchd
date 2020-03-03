
add_executable(ipwatchd analyse.c  
						config.c  
						daemonize.c  
						devinfo.c  
						genarp.c  
						ipwatchd.c  
						message.c  
						signal.c
			)
target_link_libraries(ipwatchd PRIVATE net pcap)

install(TARGETS ipwatchd
		RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
		)
