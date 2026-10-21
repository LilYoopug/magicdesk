# Normalize checkout line endings before embedding the guest's POSIX script.
file(READ "${INPUT}" script)
string(REPLACE "\r\n" "\n" script "${script}")
string(REPLACE "\\" "\\\\" script "${script}")
string(REPLACE "\"" "\\\"" script "${script}")
string(REPLACE "\n" "\\n\"\n\"" script "${script}")
file(WRITE "${OUTPUT}" "/* Generated from magicdesk_guest_session.sh. */\nstatic const char md_guest_session[] =\n\"${script}\";\n")
