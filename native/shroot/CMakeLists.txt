cmake_minimum_required(VERSION 3.24)
project(MagicDeskShroot LANGUAGES C ASM)

include(FetchContent)
FetchContent_Declare(sqlite
    URL https://www.sqlite.org/2025/sqlite-amalgamation-3500400.zip
    URL_HASH SHA256=1d3049dd0f830a025a53105fc79fd2ab9431aea99e137809d064d8ee8356b032
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(sqlite)
add_library(guest-sqlite STATIC ${sqlite_SOURCE_DIR}/sqlite3.c)
target_include_directories(guest-sqlite PUBLIC ${sqlite_SOURCE_DIR})
target_compile_definitions(guest-sqlite PUBLIC SQLITE_ENABLE_PREUPDATE_HOOK)
target_compile_definitions(guest-sqlite PRIVATE SQLITE_THREADSAFE=0 SQLITE_OMIT_LOAD_EXTENSION
    SQLITE_DQS=0 SQLITE_DEFAULT_MEMSTATUS=0 SQLITE_OMIT_DEPRECATED)
target_compile_options(guest-sqlite PRIVATE -O2 -fno-pie)

set(src ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(identity ${src}/guest_identity.c ${src}/user_namespace.c ${src}/namespace_identity.c ${src}/pid_namespace.c)
set(raw ${src}/raw.c ${src}/memory.c ${src}/raw.S)
set(wire ${src}/fs_wire.c ${src}/event_wait.c)
add_library(guest-parcels STATIC ${src}/fd_bundle.c ${src}/fs_wire.c ${src}/raw.S)
target_compile_definitions(guest-parcels PRIVATE MD_NO_START MD_USE_LIBC)
target_compile_options(guest-parcels PRIVATE -O2 -Wall -Wextra -Werror -fno-pie)
set(origins ${src}/fs_anchor.c ${src}/fs_origin_transfer.c ${src}/inode_lifetime.c ${src}/inode_custody.c ${src}/sealed_manifest.c ${src}/ipc_scope.c ${src}/mount_policy.c ${src}/mount_graph.c ${src}/resource_order.c ${src}/ofd_order.c ${src}/fd_origins.c ${src}/fd_channel.c ${src}/fd_mutation.c ${src}/fd_delivery.c ${src}/fd_table_observation.c ${src}/fd_return.c ${src}/fd_exchange.c ${src}/received_fds.c ${src}/fd_messages.c ${src}/task_descriptor.c ${src}/task_lifetime.c)
list(APPEND origins ${src}/native_mounts.c ${src}/devpts_view.c ${src}/cgroup.c ${src}/cgroup_program.c ${src}/sysfs_view.c ${src}/network_namespace.c ${src}/network_model.c ${src}/network_route.c ${src}/network_endpoint.c ${src}/network_sysctl.c
    ${src}/ipc_namespace.c ${src}/mqueue_view.c ${src}/landlock_policy.c ${src}/landlock_file.c)
set(mounts ${src}/fs_mounts.c ${src}/fs_mount_path.c ${src}/fs_mount_operations.c ${src}/fs_mount_table.c ${src}/fs_mount_change.c ${src}/fs_temporary.c ${src}/fs_overlay.c ${src}/fs_storage.c)
list(APPEND mounts ${src}/proc_paths.c ${src}/procfs_view.c ${src}/proc_fdinfo.c ${src}/fs_proc.c ${src}/fs_cgroup.c ${src}/fs_bpf.c ${src}/fs_sysfs.c ${src}/fs_mqueue.c ${src}/fs_mount_file.c ${src}/mount_source.c ${src}/fs_context.c)
set(inodes ${src}/inode_store.c ${src}/inode_db.c ${src}/inode_cache.c ${src}/inode_sqlite.c ${src}/inode_events.c ${src}/inode_watch.c ${src}/watch_queue.c ${src}/inode_path.c
    ${src}/inode_directory.c ${src}/inode_import.c ${src}/inode_socket.c ${src}/inode_backing.c ${src}/inode_snapshot.c ${src}/inode_view.c ${src}/inode_maintenance.c ${src}/inode_fifo.c ${src}/inode_channel.c ${src}/file_open.c
    ${identity} ${src}/task_registry.c ${src}/guest_domain.c ${src}/mount_namespace.c ${origins} ${src}/inode_metadata.c ${src}/inode_xattr.c ${src}/inode_capability.c ${src}/inode_acl.c ${src}/posix_acl.c)
set(namespace_engine ${src}/fs_engine.c ${src}/fs_native.c ${src}/fs_xattr.c ${src}/fs_operation.c ${src}/task_status.c ${src}/ipc_credentials.c ${src}/ipc_peer.c)
set(ipc ${src}/sysv_ipc.c ${src}/sysv_ipc_db.c ${src}/sysv_sem.c ${src}/sysv_msg.c ${src}/sysv_ipc_transport.c ${src}/ipc_storage.c ${src}/ipc_permissions.c)
set(capsules ${src}/ipc_capsule.c ${src}/fd_bundle.c ${src}/ipc_received.c ${src}/descriptor_inode.c ${src}/descriptor_parcel.c)
list(APPEND origins ${src}/mount_stream.c ${src}/mount_pin.c)
list(APPEND origins ${src}/temporary_directory.c ${src}/private_tree.c)
list(APPEND inodes ${src}/identity_snapshot.c ${src}/inode_overlay_policy.c ${src}/inode_landlock.c)
list(APPEND mounts ${src}/fs_landlock.c)
list(APPEND mounts ${src}/fs_provider.c)
list(APPEND origins ${src}/provider_tree.c)
list(APPEND inodes ${src}/provider_tree.c)
list(APPEND origins ${src}/device_events.c)
list(APPEND inodes ${src}/device_events.c)
list(APPEND origins ${src}/identity_snapshot.c)
list(APPEND inodes ${src}/mount_stream.c ${src}/mount_pin.c
    ${src}/temporary_directory.c ${src}/private_tree.c ${src}/inode_transient.c ${src}/inode_overlay.c ${src}/inode_overlay_write.c)

function(guest_executable name)
    add_executable(${name} ${ARGN})
    set_target_properties(${name} PROPERTIES OUTPUT_NAME libmagicdesk_guest_${name}.so)
    target_compile_options(${name} PRIVATE -std=c17 -O2 -Wall -Wextra -Werror -fno-pie -fno-builtin)
    target_link_options(${name} PRIVATE -static -Wl,-z,noexecstack -Wl,-z,max-page-size=16384)
    target_link_libraries(${name} PRIVATE guest-parcels)
endfunction()
function(guest_freestanding name)
    # NDK defaults assume libc; freestanding helpers use only their own raw syscall gate.
    target_compile_options(${name} PRIVATE -ffreestanding -U_FORTIFY_SOURCE
        -fno-stack-protector -fvisibility=hidden)
    target_link_options(${name} PRIVATE -nostdlib -Wl,-z,defs)
endfunction()

guest_executable(bootstrap ${src}/bootstrap.c ${src}/elf.c ${src}/exec.c ${src}/command.c ${src}/command_image.c
    ${src}/interception.c ${src}/interception_entry.S ${src}/fd_client.c ${src}/watch_calls.c ${src}/fd_filter.c ${src}/shm_calls.c ${src}/ipc_calls.c ${src}/pid_filter.c ${src}/pid_calls.c
    ${src}/file_calls.c ${src}/fs.c ${src}/proc_paths.c ${src}/proc_image.c ${src}/proc_control.c ${src}/program_files.c ${src}/task_status.c
    ${src}/namespace.c ${src}/namespace_proc.c ${src}/namespace_mount.c ${src}/namespace_mount_fd.c ${src}/namespace_bpf.c ${src}/namespace_landlock.c ${src}/socket_calls.c ${src}/socket_namespace.c ${src}/socket_identity.c ${src}/socket_ancillary.c ${src}/socket_routes.c ${src}/fd_metadata.c
    ${src}/task_receive.c ${src}/fs_client.c ${src}/fs_buffer_client.c ${src}/adapter_buffer.c ${src}/file_open.c ${wire} ${src}/raw.c ${src}/raw.S)
target_sources(bootstrap PRIVATE ${src}/descriptor_calls.c)
guest_freestanding(bootstrap)
target_compile_options(bootstrap PRIVATE -mgeneral-regs-only)
target_link_options(bootstrap PRIVATE -Wl,--image-base=0x2000000000)

guest_executable(supervisor ${src}/supervisor.c ${src}/task_resources.c ${src}/command_access.c ../command-client/wire.c ${src}/launch_registry.c ${src}/launch_peer.c ${src}/process_owner.c ${src}/interception_memory.c ${src}/interception_buffers.c ${src}/guest_domain.c
    ${src}/mount_copy_service.c ${src}/uts_namespace.c ${src}/ipc_namespace_services.c ${src}/proc_file.c ${src}/proc_sysctl.c ${src}/proc_namespace.c
    ${src}/fd_selector.c ${src}/sysv_shm.c ${src}/guest_debugger.c ${src}/process_image_view.c ${src}/fd_install.c ${src}/pid_descriptor.c
    ${src}/task_helper.c ${src}/task_quiesce.c ${src}/private_memory.c ${src}/mapping_observation.c ${src}/memory_replace.c ${src}/fd_capture.c ${src}/ipc_io_host.c ${src}/ipc_io_job.c ${src}/ipc_io_entry.S ${src}/network_io.c
    ${ipc}
    ${identity} ${src}/guest_accounts.c ${src}/elf_admission.c ${src}/elf.c ${src}/fs_client.c ${wire} ${raw}
    ${src}/fs_worker.c ${src}/fs_service.c ${src}/ipc_peer_service.c ${src}/ipc_origins.c ${src}/fs_buffer_service.c ${src}/file_open_job.c ${src}/file_snapshot.c ${src}/command_image.c ${src}/exec_prepare.c ${namespace_engine} ${src}/image_catalogue.c ${inodes} ${mounts}
    ${src}/namespace_broker.c ${src}/watch_broker.c ${src}/proc_paths.c)
target_compile_definitions(supervisor PRIVATE MD_NO_START MD_USE_LIBC)
target_sources(bootstrap PRIVATE ${src}/network_calls.c)
target_sources(supervisor PRIVATE ${capsules})
target_sources(supervisor PRIVATE ${src}/input_session.c ${src}/input_devices.c ${src}/input_uinput.c)
target_link_libraries(supervisor PRIVATE guest-sqlite guest-sha256 m)

guest_executable(run ${src}/namespace_run.c ${src}/process_owner.c ${src}/launch_environment.c ${src}/socket_routes.c ${src}/event_wait.c ${raw})
guest_freestanding(run)


guest_executable(service ${src}/service_main.c ${src}/fs_service.c ${namespace_engine} ${src}/image_catalogue.c
    ${src}/elf_admission.c ${identity} ${src}/elf.c ${src}/fs_client.c ${inodes} ${wire} ${raw} ${mounts})
target_compile_definitions(service PRIVATE MD_NO_START MD_USE_LIBC)
target_link_libraries(service PRIVATE guest-sqlite m)

include(image-dependencies.cmake)
guest_executable(image ${src}/image_main.c ${src}/image_io.c ${src}/image_json.c ${src}/launch_registry.c ${src}/image_launches.c ${src}/image_applications.c
    ${src}/image_oci.c ${src}/image_layer.c ${src}/image_pool.c ${src}/image_backup.c ${src}/image_maintenance.c
    ${src}/image_acl.c ${src}/image_publish.c ${src}/image_launch.c ${src}/image_prepare.c ${src}/image_export.c ${src}/guest_accounts.c ${src}/socket_routes.c ${inodes}
    ${namespace_engine} ${mounts} ${src}/image_catalogue.c ${src}/elf_admission.c ${identity} ${src}/proc_paths.c
    ${src}/elf.c ${src}/fs_client.c ${wire} ${raw})
target_compile_definitions(image PRIVATE MD_NO_START MD_USE_LIBC)
target_compile_options(image PRIVATE -iquote ${src})
target_include_directories(image PRIVATE ${guest_archive_SOURCE_DIR}/libarchive)
target_link_libraries(image PRIVATE guest-sqlite guest-sha256 archive_static m)

install(TARGETS bootstrap supervisor run service image RUNTIME DESTINATION lib)

option(MAGICDESK_GUEST_FIXTURES "Build standalone native fixtures" OFF)
if(MAGICDESK_GUEST_FIXTURES)
    guest_executable(jit_memory ../guest-exec-lab/test_jit_memory.c ${src}/private_memory.c ${src}/memory_replace.c ${raw})
    guest_executable(task_quiesce ../guest-exec-lab/test_task_quiesce.c ${src}/task_quiesce.c)
    target_compile_options(task_quiesce PRIVATE -iquote ${src} -UNDEBUG)
    target_compile_options(jit_memory PRIVATE -UNDEBUG)
    target_compile_definitions(jit_memory PRIVATE MD_NO_START MD_USE_LIBC)
    target_compile_options(jit_memory PRIVATE -iquote ${src})
    guest_executable(landlock_guest ../guest-exec-lab/test_landlock_guest.c)
    target_compile_options(landlock_guest PRIVATE -UNDEBUG)
    guest_executable(vm_init ../guest-exec-lab/test_vm_init.c)
    target_compile_options(vm_init PRIVATE -UNDEBUG)
    guest_executable(test_pid_namespace ../guest-exec-lab/test_pid_namespace.c ${identity})
    target_compile_options(test_pid_namespace PRIVATE -iquote ${src} -UNDEBUG)
    guest_executable(capabilities ../guest-exec-lab/test_capabilities.c)
    target_compile_options(capabilities PRIVATE -iquote ${src} -UNDEBUG)
    guest_executable(kernel_baseline ../guest-exec-lab/test_kernel_baseline.c ${src}/task_descriptor.c ${src}/task_lifetime.c)
    target_compile_options(kernel_baseline PRIVATE -iquote ${src} -UNDEBUG)
    guest_executable(test_task_resources ../guest-exec-lab/test_task_resources.c ../guest-exec-lab/test_fd_origins.c ../guest-exec-lab/test_task_receive.c ../guest-exec-lab/test_ofd_order.c ${src}/task_registry.c
        ${src}/task_resources.c ${src}/uts_namespace.c ${src}/ipc_namespace_services.c ${src}/sysv_shm.c ${src}/guest_domain.c ${src}/mount_namespace.c ${origins} ${identity} ${ipc}
        ${src}/task_receive.c ${src}/event_wait.c ${raw})
    target_compile_definitions(test_task_resources PRIVATE MD_NO_START MD_USE_LIBC)
    target_sources(test_task_resources PRIVATE ../guest-exec-lab/test_user_namespace.c ${src}/proc_file.c ${src}/proc_sysctl.c ${src}/proc_namespace.c ${src}/fd_selector.c)
    target_sources(test_task_resources PRIVATE ${src}/descriptor_inode.c ../guest-exec-lab/test_descriptor_inode.c)
    target_sources(test_task_resources PRIVATE ../guest-exec-lab/test_network_model.c ../guest-exec-lab/test_network_route.c ../guest-exec-lab/test_network_endpoint.c)
    target_compile_options(test_task_resources PRIVATE -iquote ${src} -UNDEBUG)
    target_link_libraries(test_task_resources PRIVATE guest-sqlite m)
    target_link_options(test_task_resources PRIVATE -Wl,--wrap=calloc -Wl,--wrap=malloc)
    guest_executable(resource_guest ../guest-exec-lab/test_resource_guest.c ../guest-exec-lab/test_mount_namespace_guest.c ../guest-exec-lab/test_mount_flags_guest.c ../guest-exec-lab/test_uts_namespace_guest.c ../guest-exec-lab/test_ipc_namespace_guest.c ../guest-exec-lab/test_user_namespace_guest.c)
    target_compile_options(resource_guest PRIVATE -iquote ${src} -UNDEBUG)
    target_sources(resource_guest PRIVATE ../guest-exec-lab/test_tmpfs_guest.c ../guest-exec-lab/test_namespace_handles_guest.c ../guest-exec-lab/test_overlay_guest.c)
    target_sources(resource_guest PRIVATE ../guest-exec-lab/test_setns_guest.c)
    target_sources(resource_guest PRIVATE ../guest-exec-lab/test_devpts_guest.c)
    target_sources(resource_guest PRIVATE ../guest-exec-lab/test_cgroup_guest.c)
    target_sources(resource_guest PRIVATE ../guest-exec-lab/test_keyring_guest.c)
    target_sources(resource_guest PRIVATE ../guest-exec-lab/test_native_metadata_guest.c)
    target_sources(resource_guest PRIVATE ../guest-exec-lab/test_mutation_signal_guest.c)
    target_sources(resource_guest PRIVATE ../guest-exec-lab/test_pid_namespace_guest.c)
    target_sources(resource_guest PRIVATE ../guest-exec-lab/test_proc_exec_guest.c)
    guest_executable(test_open_job ../guest-exec-lab/test_open_job.c ${src}/file_open_job.c ${src}/file_open.c ${wire} ${raw})
    target_compile_definitions(test_open_job PRIVATE MD_NO_START MD_USE_LIBC)
    target_compile_options(test_open_job PRIVATE -iquote ${src} -UNDEBUG)
    guest_executable(fd_lifecycle ../guest-exec-lab/test_fd_lifecycle.c ../guest-exec-lab/test_fd_lifecycle.S)
    target_compile_options(fd_lifecycle PRIVATE -UNDEBUG)
    guest_executable(mapping_task ../guest-exec-lab/test_mapping_task.c ${src}/mapping_observation.c)
    target_compile_options(mapping_task PRIVATE -iquote ${src} -UNDEBUG)
    guest_executable(pidfd_table ../guest-exec-lab/test_pidfd_table.c)
    target_compile_options(pidfd_table PRIVATE -UNDEBUG)
    guest_executable(fd_observation ../guest-exec-lab/test_fd_observation.c ${origins} ${src}/mount_namespace.c ${identity})
    target_compile_options(fd_observation PRIVATE -iquote ${src} -UNDEBUG)
    target_link_libraries(fd_observation PRIVATE guest-sqlite m)
    guest_executable(task_helper_fd ../guest-exec-lab/test_task_helper_fd.c ${src}/task_helper.c ${src}/task_quiesce.c
        ${src}/mapping_observation.c ${src}/interception_memory.c ${src}/interception_buffers.c ${src}/proc_paths.c
        ${origins} ${src}/mount_namespace.c ${identity} ${raw})
    target_compile_options(task_helper_fd PRIVATE -iquote ${src} -UNDEBUG)
    target_compile_definitions(task_helper_fd PRIVATE MD_NO_START MD_USE_LIBC)
    target_link_libraries(task_helper_fd PRIVATE guest-sqlite m)
    guest_executable(test_interception_buffers ../guest-exec-lab/test_interception_buffers.c ${src}/interception_buffers.c ${src}/interception_memory.c ${src}/resource_order.c)
    target_compile_options(test_interception_buffers PRIVATE -iquote ${src} -UNDEBUG)
    target_link_options(test_interception_buffers PRIVATE -Wl,--wrap=calloc -Wl,--wrap=malloc -Wl,--wrap=realloc)
    guest_executable(fs_dispatch ../guest-exec-lab/test_fs_dispatch.c ../guest-exec-lab/test_ipc_peer_worker.c ../guest-exec-lab/test_namespace_broker.c ../guest-exec-lab/test_fd_lifecycle.S
        ${src}/namespace_broker.c ${src}/watch_broker.c
        ${src}/interception_buffers.c ${src}/fs_buffer_service.c ${src}/file_open_job.c ${src}/file_snapshot.c ${src}/command_image.c ${src}/exec_prepare.c ${src}/proc_paths.c
        ${src}/fs_worker.c ${src}/fs_service.c ${src}/ipc_peer_service.c ${src}/ipc_origins.c ${src}/launch_registry.c ${src}/launch_peer.c ${namespace_engine} ${mounts} ${inodes}
        ${src}/image_catalogue.c ${src}/elf_admission.c ${src}/elf.c ${src}/fs_client.c ${wire} ${raw})
    target_compile_definitions(fs_dispatch PRIVATE MD_NO_START MD_USE_LIBC)
    target_compile_options(fs_dispatch PRIVATE -iquote ${src} -UNDEBUG)
    target_sources(fs_dispatch PRIVATE ${capsules})
    target_sources(fs_dispatch PRIVATE ${src}/input_session.c ${src}/input_devices.c ${src}/input_uinput.c)
    target_sources(fs_dispatch PRIVATE ../guest-exec-lab/test_input_session.c)
    target_link_libraries(fs_dispatch PRIVATE guest-sqlite guest-sha256 m)
    target_link_options(fs_dispatch PRIVATE -Wl,--wrap=calloc -Wl,--wrap=flock -Wl,--wrap=md_fs_send_fds -Wl,--wrap=process_vm_writev)
    guest_executable(fd_handoff ../guest-exec-lab/test_fd_handoff.c ../guest-exec-lab/test_ipc_connections.c
        ${origins} ${src}/fd_install.c ${src}/mount_namespace.c ${src}/ipc_credentials.c ${identity})
    target_compile_options(fd_handoff PRIVATE -iquote ${src} -UNDEBUG)
    target_link_libraries(fd_handoff PRIVATE guest-sqlite m)
    guest_executable(test_ipc_peer ../guest-exec-lab/test_ipc_peer.c ../guest-exec-lab/test_launch_peer.c
        ../guest-exec-lab/test_message_route.c ${origins} ${src}/mount_namespace.c
        ${src}/launch_registry.c ${src}/launch_peer.c ${src}/event_wait.c ${src}/ipc_peer.c ${src}/ipc_credentials.c
        ${identity} ${wire} ${raw})
    target_compile_definitions(test_ipc_peer PRIVATE MD_NO_START MD_USE_LIBC)
    target_compile_options(test_ipc_peer PRIVATE -iquote ${src} -UNDEBUG)
    target_link_libraries(test_ipc_peer PRIVATE guest-sqlite m)
    target_link_options(test_ipc_peer PRIVATE -Wl,--wrap=calloc)
    guest_executable(root_guest ../guest-exec-lab/test_root_guest.c)
    target_compile_options(root_guest PRIVATE -UNDEBUG)
    guest_executable(kernel_contract ../guest-exec-lab/test_kernel_contract.c
        ../guest-exec-lab/test_ancillary_contract.c)
    target_compile_options(kernel_contract PRIVATE -UNDEBUG)
    guest_executable(test_elf ../guest-exec-lab/test_elf.c ${src}/elf.c ${raw})
    guest_executable(test_input_devices ../guest-exec-lab/test_input_devices.c ${src}/input_devices.c)
    target_compile_options(test_input_devices PRIVATE -iquote ${src} -UNDEBUG)
    guest_executable(test_input_uinput ../guest-exec-lab/test_input_uinput.c ${src}/input_devices.c ${src}/input_uinput.c ${src}/event_wait.c)
    target_compile_options(test_input_uinput PRIVATE -iquote ${src} -UNDEBUG)
    guest_executable(test_input_guest ../guest-exec-lab/test_input_guest.c)
    target_compile_options(test_input_guest PRIVATE -UNDEBUG)
    target_compile_options(test_elf PRIVATE -iquote ${src} -UNDEBUG)
    target_compile_definitions(test_elf PRIVATE MD_NO_START MD_USE_LIBC)
    guest_executable(test_launch_registry ../guest-exec-lab/test_launch_registry.c ${src}/launch_registry.c)
    guest_executable(test_native_mounts ../guest-exec-lab/test_native_mounts.c ${src}/native_mounts.c)
    target_compile_options(test_native_mounts PRIVATE -iquote ${src} -UNDEBUG)
    target_link_options(test_native_mounts PRIVATE -Wl,--wrap=fopen -Wl,--wrap=fseek -Wl,--wrap=poll)
    target_compile_options(test_launch_registry PRIVATE -iquote ${src} -UNDEBUG)
    target_compile_definitions(image PRIVATE MD_INODE_TESTING)
    foreach(name inodes import rpc snapshot mounts credentials)
        guest_executable(test_${name} ../guest-exec-lab/test_${name}.c ${inodes})
        target_compile_options(test_${name} PRIVATE -iquote ${src} -UNDEBUG)
        target_compile_definitions(test_${name} PRIVATE MD_INODE_TESTING)
        target_link_libraries(test_${name} PRIVATE guest-sqlite m)
    endforeach()
    target_sources(test_credentials PRIVATE ${src}/guest_accounts.c ${namespace_engine} ${mounts}
        ${src}/image_catalogue.c ${src}/elf_admission.c ${src}/elf.c ${src}/fs_client.c ${wire} ${raw})
    target_compile_definitions(test_credentials PRIVATE MD_NO_START MD_USE_LIBC)
    target_sources(test_rpc PRIVATE ${src}/fs_client.c ${src}/fs_service.c ${namespace_engine} ${mounts}
        ${src}/image_catalogue.c ${src}/elf_admission.c ${identity} ${src}/elf.c ${wire} ${raw})
    target_compile_definitions(test_rpc PRIVATE MD_FS_TESTING MD_NO_START MD_USE_LIBC)
    target_sources(test_mounts PRIVATE ../guest-exec-lab/test_mount_copy.c ../guest-exec-lab/test_fs_anchor.c ../guest-exec-lab/test_user_namespace_fs.c ../guest-exec-lab/test_mount_alias.c ../guest-exec-lab/test_mount_policy.c ../guest-exec-lab/test_mount_graph.c ../guest-exec-lab/test_inode_custody.c ../guest-exec-lab/test_origin_transfer.c ${namespace_engine} ${mounts} ${src}/image_catalogue.c
        ${src}/elf_admission.c ${identity} ${src}/elf.c ${src}/fs_client.c ${wire} ${raw})
    target_compile_definitions(test_mounts PRIVATE MD_NO_START MD_USE_LIBC)
    target_sources(test_mounts PRIVATE ../guest-exec-lab/test_path_walk.c)
    target_sources(test_mounts PRIVATE ../guest-exec-lab/test_mount_storage.c ../guest-exec-lab/test_transient_store.c ../guest-exec-lab/test_inode_view.c ../guest-exec-lab/test_fs_context.c)
    target_sources(test_mounts PRIVATE ${capsules})
    target_link_libraries(test_mounts PRIVATE guest-sha256)
    target_link_options(test_mounts PRIVATE -Wl,--wrap=memfd_create -Wl,--wrap=mmap -Wl,--wrap=calloc)
    guest_executable(watch_guest ../guest-exec-lab/test_watch_guest.c)
    guest_executable(credentials_guest ../guest-exec-lab/test_credentials_guest.c)
    guest_executable(guest_interfaces ../guest-exec-lab/test_guest_interfaces.c)
    guest_executable(service_runtime ../guest-exec-lab/test_service_runtime.c)
    target_compile_options(service_runtime PRIVATE -UNDEBUG)
    guest_executable(ipc_credentials_guest ../guest-exec-lab/test_ipc_credentials_guest.c)
    guest_executable(ipc_io_job ../guest-exec-lab/test_ipc_io_job.c ${src}/ipc_io_job.c ${src}/ipc_io_entry.S ${src}/event_wait.c ${raw})
    target_compile_options(ipc_io_job PRIVATE -iquote ${src} -UNDEBUG)
    target_compile_definitions(ipc_io_job PRIVATE MD_NO_START MD_USE_LIBC)
    guest_executable(ipc_credentials_launch ../guest-exec-lab/test_ipc_credentials_launch.c)
    target_compile_options(watch_guest PRIVATE -UNDEBUG)
    guest_executable(watch_launch ../guest-exec-lab/test_watch_launch.c)
    guest_executable(watch_store ../guest-exec-lab/test_watch_store.c ${inodes})
    target_compile_options(watch_store PRIVATE -iquote ${src})
    target_compile_definitions(watch_store PRIVATE MD_INODE_TESTING)
    target_link_libraries(watch_store PRIVATE guest-sqlite m)
    guest_executable(watch_queue ../guest-exec-lab/test_watch_queue.c ${src}/watch_queue.c)
    guest_executable(watch_read ../guest-exec-lab/test_watch_read.c
        ../guest-exec-lab/test_watch_read.S ${src}/watch_queue.c ${src}/event_wait.c ${raw})
    target_compile_definitions(watch_read PRIVATE MD_NO_START MD_USE_LIBC)
    guest_executable(watch_activation ../guest-exec-lab/test_watch_activation.c ${src}/event_wait.c ${raw})
    target_compile_definitions(watch_activation PRIVATE MD_NO_START MD_USE_LIBC)
    guest_executable(benchmark_namespace ../guest-exec-lab/benchmark_namespace.c
        ${namespace_engine} ${src}/image_catalogue.c ${src}/elf_admission.c ${mounts}
        ${identity} ${src}/elf.c ${src}/fs_client.c ${inodes} ${wire} ${raw})
    target_compile_options(benchmark_namespace PRIVATE -iquote ${src})
    target_compile_definitions(benchmark_namespace PRIVATE MD_NO_START MD_USE_LIBC)
    target_compile_options(benchmark_namespace PRIVATE -UNDEBUG)
    target_link_libraries(benchmark_namespace PRIVATE guest-sqlite m)
endif()
